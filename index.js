'use strict'

const async = require('async')
const Base = require('bfx-facs-base')
const FastifyAuth = require('@fastify/oauth2')
const crypto = require('crypto')

const SUPPORTED_AUTHS = ['google']

class HttpdAuthFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'httpd-oauth2'
    this._hasConf = true

    this.init()
  }

  getSpecs (method) {
    const specs = {}

    switch (method) {
      case 'google':
        specs.name = 'googleOAuth2'
        specs.auth = FastifyAuth.GOOGLE_CONFIGURATION
        specs.startRedirectPath = this.conf.startRedirectPath || '/login/google'
        specs.callbackUri = this.conf.callbackUri || '/login/google/callback'
        specs.callbackUriParams = {
          access_type: 'offline'
        }
        break
    }

    return specs
  }

  injection () {
    const creds = this.conf.credentials
    const specs = this.getSpecs(this.conf.method)

    return [FastifyAuth, {
      name: specs.name,
      scope: ['profile', 'email'],
      credentials: {
        client: creds.client,
        auth: specs.auth
      },
      startRedirectPath: specs.startRedirectPath,
      callbackUri: specs.callbackUri,
      callbackUriParams: specs.callbackUriParams,
      generateStateFunction: (request) => {
        const statePayload = {
          ...request.query,
          csfr_token: crypto.randomBytes(8).toString('hex')
        }

        return Buffer.from(JSON.stringify(statePayload)).toString('base64url')
      },
      checkStateFunction: function (request, callback) {
        const stateCookie = request.cookies['oauth2-redirect-state']

        if (stateCookie && request.query.state === stateCookie) {
          callback()
          return
        }
        callback(new Error('ERR_INVALID_STATE'))
      }
    }]
  }

  resolveUserAccess (user, idField = 'email') {
    return this.conf.users.find(u => u[idField] === user)
  }

  callbackUriUI () {
    return this.conf.callbackUriUI
  }

  _start (cb) {
    async.series([
      next => { super._start(next) },
      async () => {
        if (!SUPPORTED_AUTHS.includes(this.conf.method)) {
          throw new Error('ERR_FACS_HTTPD_OAUTH2_METHOD_INVALID')
        }
      }
    ], cb)
  }
}

module.exports = HttpdAuthFacility
