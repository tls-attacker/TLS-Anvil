import { Router, Request, Response, NextFunction } from 'express';
import { ITestResultContainer, ITestResult, IState } from '../database/models';
import DB from '../database'
import { BadRequest } from '../errors';
import { TestReportService } from '../services';



export namespace UploadReportEndpoint {

  export interface IBody {
    testReport: ITestResultContainer,
    pcapDump: string,
    keylog: string,
  }

  export class Controller {
    private router: Router

    constructor(router: Router) {
      this.router = router
      router.post("/uploadReport", this.uploadReport)
    }

    private async uploadReport(req: Request, res: Response, next: NextFunction) {
      const body: IBody = req.body
      const replace: boolean = Boolean(req.query.replace)
  
      if (!body.testReport.Identifier) {
        return next(new BadRequest("Identifier is required"))
      }
      if (!body.testReport.TestClasses && !body.testReport.TestResults) {
        return next(new BadRequest("JSON is not a test report"))
      }
  
      const exists = await DB.resultContainerExistsForIdentifier(body.testReport.Identifier)
      if (exists && !replace) {
        res.status(400)
        res.send({
          success: true,
          info: "Report already exists"
        })
        return
      }
  
      if (replace && exists) {
        await DB.removeResultContainer(body.testReport.Identifier)
      }

      const testReportService = new TestReportService(body.testReport)
      const formattedReport = testReportService.prepareTestReport()
      
      DB.addResultContainer(formattedReport, body.pcapDump, body.keylog).then(() => {
        res.send({"success": true})
      }).catch((e) => {
        console.log("catched")
        console.error(e)
        next(e)
      })
    }
  }
}

