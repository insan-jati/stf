/**
* Copyright © 2019 contains code contributed by Orange SA, authors: Denis Barbaron - Licensed under the Apache license 2.0
**/

var util = require('util')

var _ = require('lodash')
// var Promise = require('bluebird')
var uuid = require('uuid')
var adbkit = require('@devicefarmer/adbkit')
var dbapi = require('../../../db/api')
var logger = require('../../../util/logger')
var wire = require('../../../wire')
var wireutil = require('../../../wire/util')

// const apiutil = require('../../../util/apiutil')
const jwtutil = require('../../../util/jwtutil')

var log = logger.createLogger('api:controllers:tdf')

module.exports = {
  tdfCreateAccessToken: tdfCreateAccessToken
, tdfDeleteAccessToken: tdfDeleteAccessToken
, tdfAddAdbPublicKey: tdfAddAdbPublicKey
, tdfDeleteAdbPublicKey: tdfDeleteAdbPublicKey
}

function validateAdmin(userEmail) {
  var admins = ['server@server.com', 'q@q.com']
  return admins.includes(userEmail)
}

async function tdfCreateAccessToken(req, res) {
  try {
    // admin authentication
    var admin = validateAdmin(req.user.email)
    if (!admin) {
      log.error('User is unauthorized to generate access token')
      return res.status(401).json({
        success: false,
        message: 'User is unauthorized to generate access token'
      })
    }

    // user validation
    var userEmail = req.body.email
    var user = await dbapi.loadUser(userEmail)
    if (user === null) {
      // if user isn't found, create one
      var userData = {
        name: userEmail.split('@')[0].replace('.', '-')
      , email: userEmail
      , ip: req.ip
      }
      var saveUser = await dbapi.saveUserAfterLogin(userData)
      if (saveUser.inserted === 1) user = userData
    }

    // create accessToken title
    var userEmail = user.email
    var userName = user.name
    var userTitle = userEmail.split('@')[0].replace('.', '-')
    userTitle = util.format('%s-%s', userTitle, uuid.v4().replace(/-/g, ''))

    // generate jwt
    var jwt = jwtutil.encode({
      payload: {
        email: userEmail
      , name: userName
      }
    , secret: req.options.secret
    })
    
    // generate access token
    var tokenId = util.format('%s-%s', uuid.v4(), uuid.v4()).replace(/-/g, '')
  
    // save data to DB
    var tokenData = {
      title: userTitle
    , id: tokenId
    , jwt: jwt
    }
    var saveToken = await dbapi.saveUserAccessToken(userEmail, tokenData)
    if (saveToken.inserted === 1) {
      res.json({
        success: true
      , title: userTitle
      , token: tokenId
      })
    }
  } catch (err) {
    log.error('Failed to generate access token "%s": ', req.user.email, err.stack)
    res.status(500).json({
      success: false
    })
  }
}

function tdfDeleteAccessToken(req, res) {
  // admin validation
  var admin = validateAdmin(req.user.email)
  if (!admin) {
    log.error('User is unauthorized to delete access token')
    return res.status(401).json({
      success: false,
      message: 'User is unauthorized to delete access token'
    })
  }

  // validate title ownership then delete the token
  var userEmail = req.body.email
  var tokenTitle = req.body.title
  dbapi.loadAccessTokens(userEmail)
    .then(function(cursor) {
      return Promise.promisify(cursor.toArray, cursor)()
        .then(function(list) {
          var tokens = list.map(token => token.title)
          var titleValid = tokens.includes(tokenTitle)
          return titleValid
        })
    })
    .then(function(token) {
      if (!token) {
        log.error('Token is not owned by this user')
        return res.status(404).json({
          success: false,
          message: 'Token is not owned by this user'
        })
      }
      else {
        return dbapi.removeUserAccessToken(userEmail, tokenTitle)
          .then(function() {
            res.json({
              success: true
            })
          })
      }
    })
    .catch(function(err) {
      log.error('Failed to delete access token "%s": ', userEmail, err.stack)
      res.status(500).json({
        success: false
      })
    })
}

async function tdfAddAdbPublicKey(req, res) {
  // admin validation
  var admin = validateAdmin(req.user.email)
  if (!admin) {
    log.error('User is unauthorized to add adb public key')
    return res.status(401).json({
      success: false,
      message: 'User is unauthorized to add adb public key'
    })
  }

  // user validation
  var userEmail = req.body.email
  var user = await dbapi.loadUser(userEmail)
  if (user === null) {
    // if user isn't found, create one
    var userData = {
      name: userEmail.split('@')[0].replace('.', '-')
    , email: userEmail
    , ip: req.ip
    }
    var saveUser = await dbapi.saveUserAfterLogin(userData)
    if (saveUser.inserted === 1) user = userData
  }

  // get payload from request body
  // var payload = req.swagger.params.adb.value
  // var data = {
  //   publickey: payload.publickey,
  //   title: payload.title
  // }
  // var userEmail = payload.email
  var data = {
    publickey: req.body.publickey,
    title: req.body.title
  }
  adbkit.util.parsePublicKey(data.publickey)
    .then(function(key) {
      return dbapi.lookupUsersByAdbKey(key.fingerprint)
        .then(function(cursor) {
          return cursor.toArray()
        })
        .then(function(users) {
          return {
            key: {
              title: data.title || key.comment
            , fingerprint: key.fingerprint
            }
          , users: users
          }
        })
    })
    .then(function(data) {
      if (data.users.length) {
        log.error('Adb public key is already added to a user:', data.users[0].email)
        return res.json({
          success: false,
          message: `Adb public key is already added to a user: ${data.users[0].email}`
        })
      }
      else {
        return dbapi.insertUserAdbKey(userEmail, data.key)
          .then(function() {
            return res.json({
              success: true,
              title: data.key.title,
              fingerprint: data.key.fingerprint
            })
          })
      }
    })
    .then(function() {
      req.options.push.send([
        req.user.group
      , wireutil.envelope(new wire.AdbKeysUpdatedMessage())
      ])
    })
    .catch(dbapi.DuplicateSecondaryIndexError, function() {
      // No-op
      return res.json({
        success: true
      })
    }).catch(function(err) {
      log.error('Failed to insert new adb key fingerprint: ', err.stack)
      return res.status(500).json({
        success: false
      , message: 'Unable to insert new adb key fingerprint to database'
      })
    })
}

async function tdfDeleteAdbPublicKey(req, res) {
  try {
    // admin validation
    var admin = validateAdmin(req.user.email)
    if (!admin) {
      log.error('User is unauthorized to add adb public key')
      return res.status(401).json({
        success: false,
        message: 'User is unauthorized to add adb public key'
      })
    }
    // user's email validation
    var userEmail = req.body.email
    var adbFingerprint = req.body.fingerprint
    var user = await dbapi.loadUser(userEmail)
    if (user === null) {
      return res.status(500).json({
        success: false,
        message: 'Email is not valid, unable to delete adb key '
      })
    }
    // adb key's title validation
    if (user.adbKeys && user.adbKeys.length > 0) {
      var adbIndex = user.adbKeys.findIndex(el => el.fingerprint === adbFingerprint)
      if (adbIndex > -1) {
        var deleteAdb = await dbapi.deleteUserAdbKey(userEmail, adbFingerprint)
        // if (deleteAdb.deleted === 1)
        return res.json({
          success: true,
        })
      }
    }
    log.error('Adb key not found or not owned by the user:', userEmail)
    return res.status(404).json({
      success: false
    , message: 'Adb key not found or not owned by the user'
    })
  } catch (err) {
    log.error('Failed to delete adb key: ', err.stack)
    return res.status(500).json({
      success: false
    , message: 'Failed to delete adb key from database'
    })
  }
}