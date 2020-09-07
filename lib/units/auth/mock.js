/**
* Copyright © 2019 contains code contributed by Orange SA, authors: Denis Barbaron - Licensed under the Apache license 2.0
**/

require('dotenv').config()
var axios = require('axios')

var http = require('http')

var express = require('express')
var validator = require('express-validator')
var cookieSession = require('cookie-session')
var bodyParser = require('body-parser')
var serveStatic = require('serve-static')
var csrf = require('csurf')
var Promise = require('bluebird')
var basicAuth = require('basic-auth')

var logger = require('../../util/logger')
var requtil = require('../../util/requtil')
var jwtutil = require('../../util/jwtutil')
var pathutil = require('../../util/pathutil')
var urlutil = require('../../util/urlutil')
var lifecycle = require('../../util/lifecycle')

const dbapi = require('../../db/api')
const TDF_HOST = process.env.TDF_HOST
const LOGIN_API = process.env.LOGIN_API
const LOGIN_URL = TDF_HOST + LOGIN_API

module.exports = function(options) {
  var log = logger.createLogger('auth-mock')
  var app = express()
  var server = Promise.promisifyAll(http.createServer(app))

  lifecycle.observe(function() {
    log.info('Waiting for client connections to end')
    return server.closeAsync()
      .catch(function() {
        // Okay
      })
  })

  // BasicAuth Middleware
  var basicAuthMiddleware = function(req, res, next) {
    function unauthorized(res) {
      res.set('WWW-Authenticate', 'Basic realm=Authorization Required')
      return res.send(401)
    }

    var user = basicAuth(req)

    if (!user || !user.name || !user.pass) {
      return unauthorized(res)
    }

    if (user.name === options.mock.basicAuth.username &&
        user.pass === options.mock.basicAuth.password) {
      return next()
    }
    else {
      return unauthorized(res)
    }
  }

  app.set('view engine', 'pug')
  app.set('views', pathutil.resource('auth/mock/views'))
  app.set('strict routing', true)
  app.set('case sensitive routing', true)

  app.use(cookieSession({
    name: options.ssid
  , keys: [options.secret]
  }))
  app.use(bodyParser.json())
  app.use(csrf())
  app.use(validator())
  app.use('/static/bower_components',
    serveStatic(pathutil.resource('bower_components')))
  app.use('/static/auth/mock', serveStatic(pathutil.resource('auth/mock')))

  app.use(function(req, res, next) {
    res.cookie('XSRF-TOKEN', req.csrfToken())
    next()
  })

  if (options.mock.useBasicAuth) {
    app.use(basicAuthMiddleware)
  }

  app.get('/', function(req, res) {
    res.redirect('/auth/mock/')
  })

  app.get('/auth/contact', function(req, res) {
    dbapi.getRootGroup().then(function(group) {
      res.status(200)
        .json({
          success: true
        , contact: group.owner
        })
    })
    .catch(function(err) {
      log.error('Unexpected error', err.stack)
      res.status(500)
        .json({
          success: false
        , error: 'ServerError'
        })
      })
  })

  app.get('/auth/mock/', function(req, res) {
    res.render('index')
  })

  app.post('/auth/api/v1/mock', function(req, res) {
    var log = logger.createLogger('auth-mock')
    log.setLocalIdentifier(req.ip)
    switch (req.accepts(['json'])) {
      case 'json':
        requtil.validate(req, function() {
            req.checkBody('email').isEmail()
            req.checkBody('password').notEmpty()
          })
          .then(function() {
            // ORIGINAL CODE
            // log.info('Authenticated "%s"', req.body.email)
            // var token = jwtutil.encode({
            //   payload: {
            //     email: req.body.email
            //   , name: req.body.name
            //   }
            // , secret: options.secret
            // , header: {
            //     exp: Date.now() + 24 * 3600
            //   }
            // })
            // res.status(200)
            //   .json({
            //     success: true
            //   , redirect: urlutil.addParams(options.appUrl, {
            //       jwt: token
            //     })
            //   })

            // TDF ADJUSTMENT
            const reqOptions = {
              headers: {
                'Content-Type': 'application/json'
              }
            , maxRedirects: 0
            , validateStatus: function(status) {
                return status < 303
              }
            }
            const data = {
              email: req.body.email
            , password: req.body.password
            }
            axios.post(LOGIN_URL, data, reqOptions)
              .then(function(resp) {
                if (resp.status === 200) {
                  log.info('Authenticated "%s"', req.body.email)
                  var token = jwtutil.encode({
                    payload: {
                      email: req.body.email
                    , name: req.body.email.split('@')[0].replace('.', '-') // parse email then replace dot with dash
                    }
                  , secret: options.secret
                  , header: {
                      exp: Date.now() + 24 * 3600
                    }
                  })
                  res.status(200)
                    .json({
                      success: true
                    , redirect: urlutil.addParams(options.appUrl, {
                        jwt: token
                      })
                    })
                }
                else {
                  res.status(401)
                    .json({
                      success: false
                    , error: 'InvalidCredentialsError'
                    })
                }
              })
              .catch(function(err) {
                log.error('Unexpected error', err.stack)
                res.status(500)
                  .json({
                    success: false
                  , error: 'ServerError'
                  })
              })
          })
          .catch(requtil.ValidationError, function(err) {
            res.status(400)
              .json({
                success: false
              , error: 'ValidationError'
              , validationErrors: err.errors
              })
          })
          .catch(function(err) {
            log.error('Unexpected error', err.stack)
            res.status(500)
              .json({
                success: false
              , error: 'ServerError'
              })
          })
        break
      default:
        res.send(406)
        break
    }
  })

  server.listen(options.port)
  log.info('Listening on port %d', options.port)
}
