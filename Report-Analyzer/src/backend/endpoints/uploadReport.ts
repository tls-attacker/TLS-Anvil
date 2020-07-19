import { Router, Request, Response, NextFunction } from 'express';
import { ITestResultContainer, ITestResult, IState } from '../database/models';
import DB from '../database'
import { BadRequest } from '../errors';
import { TestReportService } from '../services';



export namespace UploadReportEndpoint {
  export class Controller {
    private router: Router

    constructor(router: Router) {
      this.router = router
      router.post("/uploadReport", this.uploadReport)
    }

    private async uploadReport(req: Request, res: Response, next: NextFunction) {
      const body: ITestResultContainer = req.body
      const replace: boolean = Boolean(req.query.replace)
  
      if (!body.Identifier) {
        return next(new BadRequest("Identifier is required"))
      }
      if (!body.TestClasses && !body.TestResults) {
        return next(new BadRequest("JSON is not a test report"))
      }
  
      const exists = await DB.resultContainerExistsForIdentifier(body.Identifier)
      if (exists && !replace) {
        res.status(304)
        res.send({
          success: true,
          info: "Report already exists"
        })
        return
      }
  
      if (replace && exists) {
        DB.removeResultContainer(body.Identifier)
      }

      const testReportService = new TestReportService(body)
      const formattedReport = testReportService.prepareTestReport()
    

      DB.addResultContainer(formattedReport).then(() => {
        res.send({"success": true})
      }).catch((e) => {
        console.error(e)
        next(e)
      })
    }
  }
}




