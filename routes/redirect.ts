/**
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

// Allowlist of trusted domains for redirection
const allowedDomains = ['example.com', 'trustedsite.com']

module.exports = function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string

    if (toUrl && isRedirectAllowed(toUrl)) {
      // Solve challenges if specific URLs are requested
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return [
          'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
          'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
          'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
        ].includes(toUrl)
      })

      challengeUtils.solveIf(challenges.redirectChallenge, () => isUnintendedRedirect(toUrl))

      // Redirect to the validated URL
      res.redirect(toUrl)
    } else {
      // Reject unsafe or unrecognized redirects
      res.status(406).send('Unrecognized or unsafe target URL for redirect: ' + encodeURIComponent(toUrl || ''))
    }
  }
}

/**
 * Function to validate if the URL is allowed for redirection.
 * Only URLs matching the allowed domains are permitted.
 */
function isRedirectAllowed (toUrl: string): boolean {
  try {
    const parsedUrl = new URL(toUrl)

    // Check if the hostname matches any trusted domain in the allowlist
    return allowedDomains.some((domain) => parsedUrl.hostname.endsWith(domain))
  } catch (err) {
    // If URL parsing fails, deny the redirect
    return false
  }
}

/**
 * Function to check for unintended redirects.
 * Ensures the URL does not match any unintended or unsafe patterns.
 */
function isUnintendedRedirect (toUrl: string): boolean {
  const allowlist = security.redirectAllowlist || []

  // Validate that the URL starts with one of the allowlist base URLs
  return !allowlist.some((allowedUrl) => utils.startsWith(toUrl, allowedUrl))
}
