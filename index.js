'use strict'

const async = require('async')
const _ = require('lodash')
const FastifyAuth = require('@fastify/oauth2')
const Base = require('bfx-facs-base')
const debug = require('debug')('hp:server:http:oauth2')

class HttpServerAuthFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'server-http-oauth2'
    this._hasConf = true

    this.init()
  }

  injection (server) {
    return [FastifyAuth, {
      name: 'googleOAuth2',
      scope: ['profile', 'email'],
      credentials: this.conf.credentials,
      startRedirectPath: this.conf.startRedirectPath || '/login/google',
      callbackUri: this.conf.callbackUri || '/login/google/callback',
      callbackUriParams: {
        access_type: 'offline' // will tell Google to send a refreshToken too
      }
    }]
  }

  _start (cb) {
    async.series([
      next => { super._start(next) },
      async () => {
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

module.exports = HttpServerAuthFacility
