/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as models from '../models/index'
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'

import * as utils from '../lib/utils'
import challengeUtils = require('../lib/challengeUtils')

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
module.exports = function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    
    // Sanitize criteria to prevent SQL injection
    criteria = criteria.replace(/[%_]/g, '\\$&')

    models.sequelize.query(
      'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
      {
        replacements: { criteria: `%${criteria}%` },
        type: models.sequelize.QueryTypes.SELECT
      }
    ).then((products: any) => {
      res.json(products)
    }).catch((error: any) => {
      next(error)
    })
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
