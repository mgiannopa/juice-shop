/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { type Captcha } from '../data/types'
import { CaptchaModel } from '../models/captcha'

function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = `${firstTerm} ${firstOperator} ${secondTerm} ${secondOperator} ${thirdTerm}`
    const answer = evaluateExpression(firstTerm, firstOperator, secondTerm, secondOperator, thirdTerm).toString()

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

function evaluateExpression(firstTerm: number, firstOperator: string, secondTerm: number, secondOperator: string, thirdTerm: number): number {
  const firstResult = applyOperator(firstTerm, firstOperator, secondTerm)
  return applyOperator(firstResult, secondOperator, thirdTerm)
}

function applyOperator(term1: number, operator: string, term2: number): number {
  switch (operator) {
    case '+':
      return term1 + term2
    case '-':
      return term1 - term2
    case '*':
      return term1 * term2
    default:
      throw new Error('Invalid operator')
  }
}

captchas.verifyCaptcha = () => (req: Request, res: Response, next: NextFunction) => {
  CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } }).then((captcha: Captcha | null) => {
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  }).catch((error: Error) => {
    next(error)
  })
}

module.exports = captchas
