import { BadRequest } from '../errors';
import { NextFunction, Request, Response, Router } from 'express'
import DB, { FileType } from '../database';


export namespace TestReportEndpoint {


  export class Controller {
    private router: Router


    constructor(aRouter: Router) {
      this.router = aRouter

      this.router.get("/testReport/:identifier/testResult/:className/:methodName", this.getTestResult.bind(this))
      this.router.route("/testReport/:identifier")
        .get(this.getTestReport.bind(this))
        .delete(this.deleteTestReport.bind(this))

      this.router.delete("/testReport/deleteRegex", this.deleteRegex.bind(this))
      this.router.get("/testReportIdentifiers", this.getIdentifiers.bind(this))
    }


    private async getIdentifiers(req: Request, res: Response, next: NextFunction) {
      const results = await DB.testResultContainer.find().select({Identifier: 1}).lean().exec()
      const identifiers = results.map((i: any) => i.Identifier)
      identifiers.sort()
      res.send(identifiers)
    }

    private async getTestReport(req: Request, res: Response, next: NextFunction) {
      const start = new Date().getTime()
      const identifier = req.params.identifier
      const container = await DB.testResultContainer.findOne({Identifier: identifier}).lean().exec()
      if (!container) {
        return next(new BadRequest("invalid identifier"))
      }

      const testReport = await DB.getResultContainer(identifier)
      console.log(`finished in ${new Date().getTime() - start}ms`)
      res.send(testReport)
    }


    private async deleteTestReport(req: Request, res: Response, next: NextFunction) {
      DB.removeResultContainer(req.params.identifier).then(() => {
        res.send({sucess: true})
      }).catch((e) => {
        next(e)
      })
    }

    private async deleteRegex(req: Request, res: Response, next: NextFunction) {
      const regex = new RegExp(req.body.regex)
      const identifiers = await DB.testResultContainer.find({}).select({Identifier: 1}).lean().exec()
      const promises = []
      for (const i of identifiers) {
        if (regex.test(i.Identifier)) {
          promises.push(DB.removeResultContainer(i.Identifier))
        }
      }

      Promise.all(promises).then(() => {
        res.send({sucess: true})
      }).catch((e) => {
        next(e)
      })
    }


    private async getTestResult(req: Request, res: Response) {
      const identifier = req.params.identifier
      const className = req.params.className
      const methodName = req.params.methodName
    
      const testResult = await DB.getTestResult(identifier, className, methodName)
    
      res.send(testResult)
    }
  }
}


