import express from "express";
import cors from 'cors';
import DB from './database';
import { BadRequest } from './errors';
import { UploadReportEndpoint } from './endpoints';

const app = express()
let router = express.Router()
app.use(express.json({
  limit: "1GB"
}));
app.use(cors());
app.use('/api/v1', router)


new UploadReportEndpoint.Controller(router)


router.get("/testReportIdentifiers", async (req, res, next) => {
  const results = await DB.testResultContainer.find().select({Identifier: 1}).lean().exec()
  const identifiers = results.map((i) => i.Identifier)
  identifiers.sort()
  res.send(identifiers)
})


router.get("/testReport/:identifier", async (req, res, next) => {
  const identifier = req.params.identifier
  const testReport = await DB.getResultContainer(identifier)
  res.send(testReport)
})

router.get("/testReport/:identifier/testResult/:className/:methodName", async (req, res, next) => {
  const identifier = req.params.identifier
  const className = req.params.className
  const methodName = req.params.methodName

  const testResult = await DB.getTestResult(identifier, className, methodName)

  res.send(testResult)
})



app.use(function (err: Error, req: express.Request, res: express.Response, next: express.NextFunction) {
  console.error(err.stack)
  if (res.headersSent) {
    return next(err)
  }

  if (err instanceof BadRequest) {
    res.status(400)
    res.send({success: false, error: err.message})
    return
  }

  next(err)
})

DB.connect().then(() => {
  app.listen(5000, function () {
    console.log('Example app listening on port 5000!')
  })
}).catch((e) => {
  console.error("Startup failed!", e)
})
