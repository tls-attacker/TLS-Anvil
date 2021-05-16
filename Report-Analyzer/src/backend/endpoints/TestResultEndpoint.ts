import { NextFunction, Request, Response, Router } from 'express';
import pug from 'pug';
import { EditMode, TestResult } from '../../lib/const';
import DB from '../database';
import { IState, ITestResultEdit } from '../database/models';
import { BadRequest, InternalServerError } from '../errors';
import { process } from '../services/processResults';

const renderTable = pug.compileFile("./src/backend/templates/html.pug")

enum RespFormat {
  html = "html",
  raw = "raw"
}

export namespace TestResultEndpoint {


  export class Controller {
    private router: Router


    constructor(aRouter: Router) {
      this.router = aRouter

      this.router.get("/testResult/:className/:methodName", this.getTestResult.bind(this))
      this.router.post("/testResult/edit", this.submitEdit.bind(this))
    }

    private async getTestResult(req: Request, res: Response, next: NextFunction) {
      const identifiers = <string[]>req.query.identifiers
      const format = <string>req.query.format
      const className = req.params.className
      const methodName = req.params.methodName

      if (!identifiers) {
        return next(new BadRequest("Parameter identifiers is missing"))
      }

      const containers = await DB.testResultContainer
        .find({Identifier: {"$in": identifiers}})
        .select({
          Identifier: 1,
          ShortIdentifier: 1,
          "_id": 1,
        }).lean().exec()
      containers.sort((a,b) => {
        return identifiers.indexOf(a.Identifier) - identifiers.indexOf(b.Identifier)
      })
    
      const testResults = await DB.getTestResults(containers.map(i => i.Identifier), className, methodName).then(res => {
        // if a test run did not execute/have a certain test (e.g. different test suite version)
        // this is filtered out. The generated table will have less columns.
        return res.filter(i => !!i)
      })

      if (testResults.length == 0) {
        next(new BadRequest("No result found for the given identifiers."))
        return
      }
    
      if (format === RespFormat.raw) {
        res.send(testResults)
        return
      }
      

      let filteredIdentifiers = testResults.map(i => containers.filter(j => j._id.toString() === i.ContainerId.toString())[0].Identifier)
      const tableData = process(<any>testResults, <any>containers)
      const html = renderTable({
        html: format === RespFormat.html,
        identifiers: filteredIdentifiers,
        tableData: tableData.tableData,
        showTooltip: (data?: IState) => {
          if (!data) return false
          return data.AdditionalResultInformation != ''
        },
        tooltip: (data?: IState) => {
          return data.AdditionalResultInformation
        }
      })

      if (format === RespFormat.html) {
        res.send(html)
        return
      }


      res.send({
        tableData: tableData.tableData,
        filterData: tableData.filterData,
        resultData: tableData.resultData,
        html: html
      })
    }

    private async submitEdit(req: Request, res: Response, next: NextFunction) {
      interface Payload {
        editMode: EditMode,
        identifiers: string[],
        description: string,
        title: string,
        newResult: TestResult
        MethodName: string,
        ClassName: string
      }

      const data: Payload = req.body
      
      const doc: ITestResultEdit = {
        description: data.description,
        newResult: data.newResult,
        title: data.title,
        editMode: data.editMode,
        ClassName:  data.ClassName,
        MethodName: data.MethodName,
        Containers: null,
        Results: null,
      }
      
      const containerIds = await DB.testResultContainer.find({
        Identifier: {$in: data.identifiers}
      }).lean().select({_id: 1, "Identifier": 1}).exec().then((docs) => {
        return docs.map(i => i._id)
      })

      const resultIds = await DB.testResult.find({
        ContainerId: {$in: containerIds}, 
        "TestMethod.ClassName": data.ClassName, 
        "TestMethod.MethodName": data.MethodName
      }).lean().exec().then((docs) => {
        return docs.map(i => i._id)
      })

      if (data.editMode !== EditMode.allAll) {
        doc.Containers = containerIds
        doc.Results = resultIds
      }

      new DB.testResultEdit(doc).save().then(() => {
        res.send({'success': true})
      }).catch((e) => {
        next(new InternalServerError(e))
      })
    }
  }
}


