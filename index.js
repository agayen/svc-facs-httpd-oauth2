'use strict'

const async = require('async')
const FastifyAuth = require('@fastify/oauth2')
const Base = require('bfx-facs-base')
const debug = require('debug')('hp:server:http:oauth2')

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

  injection (server) {
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
      callbackUriParams: specs.callbackUriParams
    }]
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

  _stop (cb) {
    async.series([
      next => { super._stop(next) },
      async () => {
      }
    ], cb)
  }
}

module.exports = HttpdAuthFacility
