import {
  delay,
  fromBase64,
  getHardwareId,
  logDebug,
  logError,
  logInfo,
  stringify,
  toBase64,
} from './util.ts'
import type {
  Auth2faResponse,
  Auth2faVerifyResponse,
  AuthTokenResponse,
  SessionResponse,
} from './ring-types.ts'
import { ReplaySubject } from 'rxjs'
import assert from 'assert'
import type { Credentials } from '@eneris/push-receiver/dist/types.d.js'
import { Agent } from 'undici'
import { randomBytes, createHash } from 'crypto'
import { CookieJar } from 'tough-cookie'

interface RequestOptions extends RequestInit {
  responseType?: 'json' | 'buffer'
  timeout?: number
  json?: object
  dispatcher?: Agent
}

const fetchAgent = new Agent({
    connections: 6,
    pipelining: 1,
    keepAliveTimeout: 115000,
  }),
  defaultRequestOptions: RequestOptions = {
    responseType: 'json',
    method: 'GET',
    timeout: 20000,
  },
  ringErrorCodes: { [code: number]: string } = {
    7050: 'NO_ASSET',
    7019: 'ASSET_OFFLINE',
    7061: 'ASSET_CELL_BACKUP',
    7062: 'UPDATING',
    7063: 'MAINTENANCE',
  },
  clientApiBaseUrl = 'https://api.ring.com/clients_api/',
  deviceApiBaseUrl = 'https://api.ring.com/devices/v1/',
  commandsApiBaseUrl = 'https://api.ring.com/commands/v1/',
  appApiBaseUrl = 'https://prd-api-us.prd.rings.solutions/api/v1/',
  oauthBaseUrl = 'https://oauth.ring.com',
  apiVersion = 11,
  oauthRedirectOrigins = new Set([
    'https://oauth.ring.com',
    'https://ring.com',
  ]),
  oauthUserAgent = 'android:com.ringapp',
  oauthRequestTimeout = 20000,
  maxOauthRedirects = 5

function generateCodeVerifier() {
  return randomBytes(32).toString('base64url')
}

function generateCodeChallenge(codeVerifier: string) {
  return createHash('sha256').update(codeVerifier).digest('base64url')
}

function generateState() {
  return randomBytes(16).toString('hex')
}

function resolveOauthUrl(location: string, currentUrl: string): URL {
  const nextUrl = new URL(location, currentUrl)
  if (!oauthRedirectOrigins.has(nextUrl.origin)) {
    throw new Error('Refusing Ring OAuth redirect to an untrusted origin')
  }

  return nextUrl
}

async function storeResponseCookies(
  cookieJar: CookieJar,
  response: Response,
  requestUrl: string,
) {
  for (const cookie of response.headers.getSetCookie()) {
    await cookieJar.setCookie(cookie, requestUrl)
  }
}

async function oauthHeaders(
  cookieJar: CookieJar,
  requestUrl: string,
  additionalHeaders: Record<string, string> = {},
) {
  const cookie = await cookieJar.getCookieString(requestUrl)

  return {
    'User-Agent': oauthUserAgent,
    ...additionalHeaders,
    ...(cookie ? { Cookie: cookie } : {}),
  }
}

interface PendingPkceState {
  codeVerifier: string
  state: string
  csrfToken: string
  cookieJar: CookieJar
  redirectUri: string
}

export function clientApi(path: string) {
  return clientApiBaseUrl + path
}

export function deviceApi(path: string) {
  return deviceApiBaseUrl + path
}

export function commandsApi(path: string) {
  return commandsApiBaseUrl + path
}

export function appApi(path: string) {
  return appApiBaseUrl + path
}

export interface ExtendedResponse {
  responseTimestamp: number
  timeMillis: number
}

interface ResponseError extends Error {
  response: Pick<Response, 'headers' | 'status'> & { body: any }
}

async function responseToError(response: Response) {
  const error = new Error() as ResponseError
  error.response = {
    headers: response.headers,
    status: response.status,
    body: null,
  }

  try {
    const bodyText = await response.text()

    try {
      error.response.body = JSON.parse(bodyText)
    } catch {
      error.response.body = bodyText
    }
  } catch {
    // ignore
  }

  return error
}

function isAuthTokenResponse(value: unknown): value is AuthTokenResponse {
  if (!value || typeof value !== 'object') {
    return false
  }

  const token = value as Partial<AuthTokenResponse>
  return (
    typeof token.access_token === 'string' &&
    token.access_token.length > 0 &&
    typeof token.refresh_token === 'string' &&
    token.refresh_token.length > 0
  )
}

function oauthErrorSummary(error: unknown) {
  const response = (error as Partial<ResponseError>)?.response
  if (response && typeof response.status === 'number') {
    const body = response.body,
      errorCode =
        body &&
        typeof body === 'object' &&
        typeof body.error === 'string' &&
        /^[a-z0-9_.-]{1,64}$/i.test(body.error)
          ? body.error
          : undefined
    return `status ${response.status}${errorCode ? `, error ${errorCode}` : ''}`
  }

  if (error instanceof Error) {
    const safeMessagePrefixes = [
      'Refusing Ring OAuth redirect',
      'State mismatch in OAuth response',
      'Unable to extract CSRF token',
      'Ring OAuth ',
      'Ring sign-in ',
      'No pending PKCE flow',
      '2FA verification failed',
      'Verification Code is invalid or expired',
      'No location header',
      'Expected redirect from authorize',
      'Failed to get authorization code',
    ]
    if (
      safeMessagePrefixes.some((prefix) => error.message.startsWith(prefix))
    ) {
      return error.message
    }

    return error.name
  }

  return 'unknown OAuth error'
}

async function requestWithRetry<T>(
  requestOptions: RequestOptions & { url: string; allowNoResponse?: boolean },
  retryCount = 0,
): Promise<T & ExtendedResponse> {
  if (typeof fetch !== 'function') {
    throw new Error(
      `Your current NodeJS version (${process.version}) is too old to support this plugin.  Please upgrade to the latest LTS version of NodeJS.`,
    )
  }

  try {
    if (requestOptions.json || requestOptions.responseType === 'json') {
      requestOptions.headers = {
        ...requestOptions.headers,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      }

      if (requestOptions.json) {
        requestOptions.body = JSON.stringify(requestOptions.json)
      }
      delete requestOptions.json
    }

    const options = {
      ...defaultRequestOptions,
      ...requestOptions,
      dispatcher: fetchAgent,
    }

    // If a timeout is provided, create an AbortSignal for it
    if (options.timeout && !options.signal) {
      options.signal = AbortSignal.timeout(options.timeout)
    }

    // make the fetch request
    const response = await fetch(options.url, options),
      headers = response.headers

    if (!response.ok) {
      const error = await responseToError(response)
      throw error
    }

    let data: T & ExtendedResponse

    if (options.responseType === 'buffer') {
      const arrayBuffer = await response.arrayBuffer()
      data = Buffer.from(arrayBuffer) as any
    } else {
      const text = await response.text()
      try {
        data = JSON.parse(text)
      } catch {
        data = text as any
      }
    }

    if (data !== null && typeof data === 'object') {
      const date = headers.get('date')
      if (date) {
        data.responseTimestamp = new Date(date).getTime()
      }

      const xTime = headers.get('x-time-millis')
      if (xTime) {
        data.timeMillis = Number(xTime)
      }
    }
    return data
  } catch (e: any) {
    if (!e.response && !requestOptions.allowNoResponse) {
      if (retryCount > 0) {
        let detailedError = `Error: ${e.message}`
        detailedError += e.cause?.message ? `, Cause: ${e.cause.message}` : ''
        detailedError += e.cause?.code ? `, Code: ${e.cause.code}` : ''
        logError(
          `Retry #${retryCount} failed to reach Ring server at ${requestOptions.url}.  ${detailedError}.  Trying again in 5 seconds...`,
        )
        if (e.message.includes('NGHTTP2_ENHANCE_YOUR_CALM')) {
          logError(
            `There is a known issue with your current NodeJS version (${process.version}).  Please see https://github.com/dgreif/ring/wiki/NGHTTP2_ENHANCE_YOUR_CALM-Error for details`,
          )
        }
        logDebug(e)
      }

      await delay(5000)
      return requestWithRetry(requestOptions, retryCount + 1)
    }
    throw e
  }
}

export interface EmailAuth {
  email: string
  password: string
  systemId?: string
}

export interface RefreshTokenAuth {
  refreshToken: string
  systemId?: string
}

export interface SessionOptions {
  controlCenterDisplayName?: string
}

/**
 * When a "refreshToken" string is created by this client, it contains not only the refresh token needed to auth with
 * Ring servers, but also the hardware id and other information that needs to be stored across usages of the client
 * The Ring refresh token (rt field) will change over time, but the other fields can be carried over between restarts.
 */
interface AuthConfig {
  rt: string // Refresh Token for Auth
  hid?: string // Hardware ID, to stay consistent after initial token creation
  pnc?: Credentials // Push Notification Credentials
}

function parseAuthConfig(rawRefreshToken?: string): AuthConfig | undefined {
  if (!rawRefreshToken) {
    return
  }

  try {
    const config = JSON.parse(fromBase64(rawRefreshToken))
    assert(config)
    assert(config.rt)
    return config
  } catch {
    return {
      rt: rawRefreshToken,
    }
  }
}

export class RingRestClient {
  public refreshToken
  private authConfig
  private hardwareIdPromise
  private _authPromise: Promise<AuthTokenResponse> | undefined
  private timeouts: ReturnType<typeof setTimeout>[] = []
  private clearPreviousAuth() {
    this._authPromise = undefined
  }
  private get authPromise() {
    if (!this._authPromise) {
      const authPromise = this.getAuth()
      this._authPromise = authPromise

      authPromise
        .then(({ expires_in }) => {
          // clear the existing auth promise 1 minute before it expires
          const timeout = setTimeout(
            () => {
              if (this._authPromise === authPromise) {
                this.clearPreviousAuth()
              }
            },
            ((expires_in || 3600) - 60) * 1000,
          )
          this.timeouts.push(timeout)
        })
        .catch(() => {
          // ignore these errors here, they should be handled by the function making a rest request
        })
    }

    return this._authPromise
  }
  private sessionPromise?: Promise<SessionResponse> = undefined
  public using2fa = false
  public promptFor2fa?: string
  public onRefreshTokenUpdated = new ReplaySubject<{
    oldRefreshToken?: string
    newRefreshToken: string
  }>(1)
  public onSession = new ReplaySubject<SessionResponse>(1)
  public readonly baseSessionMetadata
  private authOptions

  constructor(authOptions: (EmailAuth | RefreshTokenAuth) & SessionOptions) {
    this.authOptions = authOptions
    this.refreshToken =
      'refreshToken' in authOptions ? authOptions.refreshToken : undefined
    this.authConfig = parseAuthConfig(this.refreshToken)
    this.hardwareIdPromise =
      this.authConfig?.hid || getHardwareId(authOptions.systemId)
    this.baseSessionMetadata = {
      api_version: apiVersion,
      device_model: authOptions.controlCenterDisplayName ?? 'ring-client-api',
    }
  }

  private pendingPkceState?: PendingPkceState

  private async extractCsrfToken(html: string, cookieJar: CookieJar) {
    const csrfCookieNames = new Set([
      'csrf-token',
      'csrfToken',
      'csrf_token',
      '_csrf',
      'XSRF-TOKEN',
    ])
    for (const cookie of await cookieJar.getCookies(
      `${oauthBaseUrl}/oauth/v2/signin`,
    )) {
      if (csrfCookieNames.has(cookie.key) && cookie.value) {
        return cookie.value
      }
    }

    // Ring has used both ids for JSON bootstrap data across auth page versions.
    for (const scriptId of ['__NEXT_DATA__', 'oauth-args']) {
      const escapedId = scriptId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
        scriptMatch = html.match(
          new RegExp(
            `<script[^>]*id=["']${escapedId}["'][^>]*>(.*?)<\\/script>`,
            's',
          ),
        )
      if (!scriptMatch) {
        continue
      }

      try {
        const csrfToken = this.findCsrfInObject(JSON.parse(scriptMatch[1]))
        if (csrfToken) return csrfToken
      } catch {
        // Continue with the non-JSON fallbacks below.
      }
    }

    // Try hidden input field (various name patterns)
    const inputMatch =
      html.match(/name="csrf-token"[^>]*value="([^"]+)"/) ||
      html.match(/value="([^"]+)"[^>]*name="csrf-token"/) ||
      html.match(/name="csrfToken"[^>]*value="([^"]+)"/) ||
      html.match(/value="([^"]+)"[^>]*name="csrfToken"/) ||
      html.match(/name="_csrf"[^>]*value="([^"]+)"/) ||
      html.match(/value="([^"]+)"[^>]*name="_csrf"/)
    if (inputMatch) return inputMatch[1]

    // Try meta tag
    const metaMatch =
      html.match(/meta[^>]*name="csrf-token"[^>]*content="([^"]+)"/) ||
      html.match(/meta[^>]*name="csrfToken"[^>]*content="([^"]+)"/)
    if (metaMatch) return metaMatch[1]

    // Try any JavaScript variable assignment that looks like a CSRF token
    const jsMatch = html.match(
      /["']csrf[-_]?[Tt]oken["']\s*[=:]\s*["']([^"']+)["']/,
    )
    if (jsMatch) return jsMatch[1]

    throw new Error('Unable to extract CSRF token from Ring OAuth page')
  }

  private findCsrfInObject(obj: unknown, depth = 0): string | undefined {
    if (!obj || typeof obj !== 'object' || depth > 5) return undefined
    const record = obj as Record<string, unknown>
    for (const key of Object.keys(record)) {
      const lowerKey = key.toLowerCase()
      if (
        (lowerKey === 'csrftoken' ||
          lowerKey === 'csrf' ||
          lowerKey === 'csrf-token' ||
          lowerKey === 'csrf_token') &&
        typeof record[key] === 'string'
      ) {
        return record[key]
      }
      const found = this.findCsrfInObject(record[key], depth + 1)
      if (found) return found
    }
    return undefined
  }

  private async initiatePkceFlow(): Promise<void> {
    const codeVerifier = generateCodeVerifier(),
      codeChallenge = generateCodeChallenge(codeVerifier),
      state = generateState(),
      hardwareId = await this.hardwareIdPromise,
      redirectUri = 'https://ring.com/signin/callback',
      cookieJar = new CookieJar(),
      params = new URLSearchParams({
        redirect_uri: redirectUri,
        client_id: 'ring_official_android',
        response_type: 'code',
        prompt: 'login',
        state,
        scope: 'client',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        device_model: 'ring-client-api',
        app_version: '3.102.0',
        dark_mode: 'false',
        device_brand: 'nodejs',
        device_os_version: process.version,
        app_brand: 'ring',
        hardware_id: hardwareId,
      })

    // Follow redirects manually so cookies remain scoped to their real host/path.
    let currentUrl = new URL(`${oauthBaseUrl}/oauth/v2/authorize?${params}`),
      html = ''

    for (let i = 0; i < maxOauthRedirects; i++) {
      const requestUrl = currentUrl.toString(),
        options = {
          method: 'GET',
          redirect: 'manual' as const,
          headers: await oauthHeaders(cookieJar, requestUrl, {
            Accept: 'text/html,application/xhtml+xml,application/json',
          }),
          dispatcher: fetchAgent,
          signal: AbortSignal.timeout(oauthRequestTimeout),
        },
        response = await fetch(requestUrl, options)
      await storeResponseCookies(cookieJar, response, requestUrl)

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location')
        if (!location) {
          throw new Error('Ring OAuth redirect did not include a location')
        }
        currentUrl = resolveOauthUrl(location, requestUrl)
        continue
      }

      if (!response.ok) {
        throw new Error(`Ring OAuth sign-in page returned ${response.status}`)
      }

      html = await response.text()
      break
    }

    if (!html) {
      throw new Error('Ring OAuth redirect limit exceeded')
    }

    const csrfToken = await this.extractCsrfToken(html, cookieJar)
    logDebug('Ring OAuth sign-in session initialized')

    this.pendingPkceState = {
      codeVerifier,
      state,
      csrfToken,
      cookieJar,
      redirectUri,
    }
  }

  private async submitCredentials(): Promise<void> {
    const { authOptions } = this
    if (!('email' in authOptions) || !this.pendingPkceState) {
      throw new Error('No pending PKCE flow or email credentials')
    }

    const { csrfToken, cookieJar } = this.pendingPkceState,
      body = new URLSearchParams({
        username: authOptions.email,
        password: authOptions.password,
        'csrf-token': csrfToken,
      }),
      requestUrl = `${oauthBaseUrl}/oauth/v2/signin`,
      signinPostOptions = {
        method: 'POST',
        redirect: 'manual' as const,
        headers: await oauthHeaders(cookieJar, requestUrl, {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json,text/html',
          Origin: oauthBaseUrl,
          Referer: `${oauthBaseUrl}/oauth/v2/signin`,
        }),
        body: body.toString(),
        dispatcher: fetchAgent,
        signal: AbortSignal.timeout(oauthRequestTimeout),
      },
      response = await fetch(requestUrl, signinPostOptions)

    await storeResponseCookies(cookieJar, response, requestUrl)
    logDebug(`Ring OAuth credential response status: ${response.status}`)

    if (response.status === 412) {
      // 2FA required
      const responseData = (await response
        .json()
        .catch(() => ({}))) as Auth2faResponse
      this.using2fa = true

      if ('tsv_state' in responseData) {
        const { tsv_state, phone } = responseData,
          prompt =
            tsv_state === 'totp'
              ? 'from your authenticator app'
              : `sent to ${phone} via ${tsv_state}`

        this.promptFor2fa = `Please enter the code ${prompt}`
      } else {
        this.promptFor2fa = 'Please enter the code sent to your text/email'
      }

      throw new Error(
        'Your Ring account is configured to use 2-factor authentication (2fa).  See https://github.com/dgreif/ring/wiki/Refresh-Tokens for details.',
      )
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (location) {
        resolveOauthUrl(location, requestUrl)
      }
      return
    }

    if (!response.ok) {
      throw new Error(`Ring sign-in rejected credentials (${response.status})`)
    }
  }

  private async verify2fa(code: string): Promise<void> {
    if (!this.pendingPkceState) {
      throw new Error('No pending PKCE flow state for 2FA verification')
    }

    const { csrfToken, cookieJar } = this.pendingPkceState,
      body = new URLSearchParams({
        '2fa_code': code,
        'csrf-token': csrfToken,
        remember_me: 'false',
      }),
      requestUrl = `${oauthBaseUrl}/oauth/v2/2fa/verify`,
      verifyOptions = {
        method: 'POST',
        headers: await oauthHeaders(cookieJar, requestUrl, {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          Origin: oauthBaseUrl,
          Referer: `${oauthBaseUrl}/oauth/v2/signin`,
        }),
        body: body.toString(),
        dispatcher: fetchAgent,
        signal: AbortSignal.timeout(oauthRequestTimeout),
      },
      response = await fetch(requestUrl, verifyOptions)

    await storeResponseCookies(cookieJar, response, requestUrl)

    logDebug(`Ring OAuth 2FA response status: ${response.status}`)

    if (response.status === 400 || response.status === 401) {
      this.promptFor2fa = 'Invalid 2fa code entered.  Please try again.'
      throw new Error('Verification Code is invalid or expired')
    }

    if (response.status !== 200 && response.status !== 201) {
      throw new Error(`2FA verification failed with status ${response.status}`)
    }

    const verifyBody = (await response
      .json()
      .catch(() => ({}))) as Partial<Auth2faVerifyResponse>
    if (verifyBody.redirect_url) {
      resolveOauthUrl(verifyBody.redirect_url, requestUrl)
    }
    logDebug('Ring OAuth 2FA verification succeeded')
  }

  private async getAuthorizationCode(): Promise<string> {
    if (!this.pendingPkceState) {
      throw new Error('No pending PKCE flow state')
    }

    const { state, cookieJar } = this.pendingPkceState

    // After 2FA, the server remembers the original authorize params from the session.
    // We just need to revisit /oauth/v2/authorize with the session cookies.
    let authorizeUrl = new URL(`${oauthBaseUrl}/oauth/v2/authorize`)

    // Follow redirects manually to find the one with the authorization code
    for (let i = 0; i < maxOauthRedirects; i++) {
      const requestUrl = authorizeUrl.toString(),
        reqOptions = {
          method: 'GET',
          redirect: 'manual' as const,
          headers: await oauthHeaders(cookieJar, requestUrl, {
            Accept: 'text/html,application/xhtml+xml,application/json',
          }),
          dispatcher: fetchAgent,
          signal: AbortSignal.timeout(oauthRequestTimeout),
        },
        response = await fetch(requestUrl, reqOptions)
      await storeResponseCookies(cookieJar, response, requestUrl)

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location')

        if (!location) {
          throw new Error('No location header in authorize redirect')
        }

        const redirectUrl = resolveOauthUrl(location, requestUrl),
          code = redirectUrl.searchParams.get('code'),
          returnedState = redirectUrl.searchParams.get('state')

        if (code) {
          if (returnedState !== state) {
            throw new Error('State mismatch in OAuth response')
          }
          return code
        }

        // No code yet — follow this redirect
        authorizeUrl = redirectUrl
        continue
      }

      throw new Error(
        `Expected redirect from authorize but got ${response.status}`,
      )
    }

    throw new Error(
      'Failed to get authorization code after following redirects',
    )
  }

  private async exchangeCodeForTokens(
    code: string,
  ): Promise<AuthTokenResponse> {
    if (!this.pendingPkceState) {
      throw new Error('No pending PKCE flow state')
    }

    const { codeVerifier, redirectUri } = this.pendingPkceState,
      hardwareId = await this.hardwareIdPromise,
      body = new URLSearchParams({
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        client_id: 'ring_official_android',
      }),
      tokenOptions = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          'User-Agent': oauthUserAgent,
          hardware_id: hardwareId,
        },
        body: body.toString(),
        dispatcher: fetchAgent,
        signal: AbortSignal.timeout(oauthRequestTimeout),
      },
      response = await fetch(`${oauthBaseUrl}/oauth/token`, tokenOptions)

    if (!response.ok) {
      const error = await responseToError(response)
      throw error
    }

    const tokenResponse: unknown = await response.json()
    if (!isAuthTokenResponse(tokenResponse)) {
      throw new Error('Ring OAuth token response was incomplete')
    }

    // Clean up PKCE state
    this.pendingPkceState = undefined

    return tokenResponse
  }

  private async refreshWithToken(): Promise<AuthTokenResponse> {
    const hardwareId = await this.hardwareIdPromise,
      body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.authConfig!.rt,
        client_id: 'ring_official_android',
        scope: 'client',
      }),
      response: unknown = await requestWithRetry<unknown>({
        url: `${oauthBaseUrl}/oauth/token`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          'User-Agent': oauthUserAgent,
          hardware_id: hardwareId,
        },
        body: body.toString(),
      })

    if (!isAuthTokenResponse(response)) {
      throw new Error('Ring OAuth refresh response was incomplete')
    }

    return response
  }

  private async authenticateWithPkce(
    twoFactorAuthCode?: string,
  ): Promise<AuthTokenResponse> {
    // Track whether we've passed the 2FA stage so we can distinguish
    // "need 2FA code" errors from post-2FA errors
    let past2fa = false

    try {
      if (twoFactorAuthCode && this.pendingPkceState) {
        // We have a 2FA code and an existing PKCE session — verify and continue
        await this.verify2fa(twoFactorAuthCode)
        past2fa = true
      } else {
        // Start fresh PKCE flow
        await this.initiatePkceFlow()
        await this.submitCredentials()
        // If we reach here without throwing, no 2FA was needed
        past2fa = true
      }

      // Get the authorization code via redirect
      logDebug('Getting authorization code...')
      const code = await this.getAuthorizationCode()

      // Exchange code for tokens
      logDebug('Exchanging code for tokens...')
      const tokenResponse = await this.exchangeCodeForTokens(code)
      this.using2fa = false
      this.promptFor2fa = undefined
      return tokenResponse
    } catch (error: any) {
      // Re-throw 2FA prompt errors as-is (only when we haven't passed 2FA yet)
      if (this.using2fa && this.promptFor2fa && !past2fa) {
        throw error
      }

      this.pendingPkceState = undefined
      const authTypeMessage =
          'refreshToken' in this.authOptions
            ? 'refresh token is'
            : 'email and password are',
        errorMessage =
          `Failed to fetch oauth token from Ring. Verify that your ${authTypeMessage} correct.` +
          ` (${oauthErrorSummary(error)})`
      logError(errorMessage)
      throw new Error(errorMessage, { cause: error })
    }
  }

  private async updateTokens(response: AuthTokenResponse) {
    const oldRefreshToken = this.refreshToken,
      hardwareId = await this.hardwareIdPromise

    this.authConfig = {
      ...this.authConfig,
      rt: response.refresh_token,
      hid: hardwareId,
    }
    this.refreshToken = toBase64(JSON.stringify(this.authConfig))

    this.onRefreshTokenUpdated.next({
      oldRefreshToken,
      newRefreshToken: this.refreshToken,
    })

    return {
      ...response,
      refresh_token: this.refreshToken,
    }
  }

  async getAuth(twoFactorAuthCode?: string): Promise<AuthTokenResponse> {
    // If we have a refresh token and no 2FA code, use refresh flow
    if (this.authConfig?.rt && !twoFactorAuthCode) {
      try {
        const response = await this.refreshWithToken()
        return this.updateTokens(response)
      } catch (e) {
        // Refresh token failed — clear it and try email/password if available
        this.refreshToken = undefined
        this.authConfig = undefined
        logError(`Ring OAuth refresh failed (${oauthErrorSummary(e)})`)
        return this.getAuth()
      }
    }

    // Email/password auth via PKCE
    const { authOptions } = this
    if ('email' in authOptions) {
      const response = await this.authenticateWithPkce(twoFactorAuthCode)
      return this.updateTokens(response)
    }

    throw new Error(
      'Refresh token is not valid.  Unable to authenticate with Ring servers.  See https://github.com/dgreif/ring/wiki/Refresh-Tokens',
    )
  }

  private async fetchNewSession(authToken: AuthTokenResponse) {
    return requestWithRetry<SessionResponse>({
      url: clientApi('session'),
      json: {
        device: {
          hardware_id: await this.hardwareIdPromise,
          metadata: this.baseSessionMetadata,
          os: 'android', // can use android, ios, ring-site, windows for sure
        },
      },
      method: 'POST',
      headers: {
        authorization: `Bearer ${authToken.access_token}`,
      },
    })
  }

  getSession(): Promise<SessionResponse> {
    return this.authPromise.then(async (authToken) => {
      try {
        const session = await this.fetchNewSession(authToken)
        this.onSession.next(session)
        return session
      } catch (e: any) {
        const response = (e as ResponseError).response || {}

        if (response.status === 401) {
          await this.refreshAuth()
          return this.getSession()
        }

        if (response.status === 429) {
          const retryAfter = e.response.headers.get('retry-after'),
            waitSeconds = isNaN(retryAfter)
              ? 200
              : Number.parseInt(retryAfter, 10)

          logError(
            `Session response rate limited. Waiting to retry after ${waitSeconds} seconds`,
          )
          await delay((waitSeconds + 1) * 1000)

          logInfo('Retrying session request')
          return this.getSession()
        }
        throw e
      }
    })
  }

  private async refreshAuth() {
    this.clearPreviousAuth()
    await this.authPromise
  }

  private refreshSession() {
    this.sessionPromise = this.getSession()

    this.sessionPromise
      .finally(() => {
        // Refresh the session every 12 hours
        // This is needed to keep the session alive for users outside the US, due to Data Residency laws
        // We believe Ring is clearing the session info after ~24 hours, which breaks Push Notifications
        const timeout = setTimeout(
          () => {
            this.refreshSession()
          },
          12 * 60 * 60 * 1000,
        ) // 12 hours
        this.timeouts.push(timeout)
      })
      .catch((e) => logError(e))
  }

  async request<T = void>(
    options: RequestOptions & { url: string; allowNoResponse?: boolean },
  ): Promise<T & ExtendedResponse> {
    const hardwareId = await this.hardwareIdPromise,
      url = options.url! as string,
      initialSessionPromise = this.sessionPromise

    try {
      await initialSessionPromise
      const authTokenResponse = await this.authPromise

      return await requestWithRetry<T>({
        ...options,
        headers: {
          ...options.headers,
          authorization: `Bearer ${authTokenResponse.access_token}`,
          hardware_id: hardwareId,
          'User-Agent': 'android:com.ringapp',
        },
      })
    } catch (e: any) {
      const response = (e as ResponseError).response || {}

      if (response.status === 401) {
        await this.refreshAuth()
        return this.request(options)
      }

      if (response.status === 504) {
        // Gateway Timeout.  These should be recoverable, but wait a few seconds just to be on the safe side
        await delay(5000)
        return this.request(options)
      }

      if (
        response.status === 404 &&
        response.body &&
        Array.isArray(response.body.errors)
      ) {
        const errors = response.body.errors,
          errorText = errors
            .map((code: number) => ringErrorCodes[code])
            .filter((x?: string) => x)
            .join(', ')

        if (errorText) {
          logError(
            `http request failed.  ${url} returned errors: (${errorText}).  Trying again in 20 seconds`,
          )

          await delay(20000)
          return this.request(options)
        }
        logError(
          `http request failed.  ${url} returned unknown errors: (${stringify(
            errors,
          )}).`,
        )
      }

      if (response.status === 404 && url.startsWith(clientApiBaseUrl)) {
        logError('404 from endpoint ' + url)
        if (response.body?.error?.includes(hardwareId)) {
          logError(
            'Session hardware_id not found.  Creating a new session and trying again.',
          )
          if (this.sessionPromise === initialSessionPromise) {
            this.refreshSession()
          }
          return this.request(options)
        }

        throw new Error(
          'Not found with response: ' + stringify(response.body),
          {
            cause: e,
          },
        )
      }

      if (response.status) {
        logError(
          `Request to ${url} failed with status ${
            response.status
          }. Response body: ${stringify(response.body)}`,
        )
      } else if (!options.allowNoResponse) {
        logError(`Request to ${url} failed:`)
        logError(e)
      }

      throw e
    }
  }

  getCurrentAuth() {
    return this.authPromise
  }

  clearTimeouts() {
    this.timeouts.forEach(clearTimeout)
  }

  get _internalOnly_pushNotificationCredentials() {
    return this.authConfig?.pnc
  }

  set _internalOnly_pushNotificationCredentials(
    credentials: Credentials | undefined,
  ) {
    if (!this.refreshToken || !this.authConfig) {
      throw new Error(
        'Cannot set push notification credentials without a refresh token',
      )
    }

    const oldRefreshToken = this.refreshToken
    this.authConfig = {
      ...this.authConfig,
      pnc: credentials,
    }

    // SOMEDAY: refactor the conversion from auth config to refresh token - DRY from above
    const newRefreshToken = toBase64(JSON.stringify(this.authConfig))
    if (newRefreshToken === oldRefreshToken) {
      // No change, so we don't need to emit an updated refresh token
      return
    }

    // Save and emit the updated refresh token
    this.refreshToken = newRefreshToken
    this.onRefreshTokenUpdated.next({
      oldRefreshToken,
      newRefreshToken,
    })
  }
}
