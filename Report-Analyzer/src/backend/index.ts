import cors from 'cors';
import { KeylogFileEndpoint } from './endpoints/keylogfile';
import express from "express";
import DB, { FileType } from './database';
import { UploadReportEndpoint } from './endpoints';
import { BadRequest } from './errors';
import { PcapEndpoint } from './endpoints/pcap';

const app = express()
let router = express.Router()
app.use(express.json({
  limit: "1GB"
}));

if (!process.env.PRODUCTION) {
  app.use(cors());
} else {
  app.use(express.static('dist'))
}

app.use('/api/v1', router)


new UploadReportEndpoint.Controller(router)
new KeylogFileEndpoint.Controller(router)
new PcapEndpoint.Controller(router)


router.get("/testReportIdentifiers", async (req, res, next) => {
  const results = await DB.testResultContainer.find().select({Identifier: 1}).lean().exec()
  const identifiers = results.map((i: any) => i.Identifier)
  identifiers.sort()
  res.send(identifiers)
})



router.delete("/testReport/deleteRegex", async (req, res, next) => {
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
})

router.route("/testReport/:identifier").get(async (req, res, next) => {
  const start = new Date().getTime()
  const identifier = req.params.identifier
  const container = await DB.testResultContainer.findOne({Identifier: identifier}).lean().exec()
  if (!container) {
    return next(new BadRequest("invalid identifier"))
  }

  const cacheHeader = req.header('If-None-Match')
  const etag = container.updatedAt.toISOString() + identifier
  res.set('ETag', etag)
  if (cacheHeader && cacheHeader == etag) {
    res.status(304)
    res.send()
    return
  }

  const testReport = await DB.getResultContainer(identifier)
  console.log(`finished in ${new Date().getTime() - start}ms`)
  res.send(testReport)
}).delete(async (req, res, next) => {
  DB.removeResultContainer(req.params.identifier).then(() => {
    res.send({sucess: true})
  }).catch((e) => {
    next(e)
  })
})



router.get("/testReport/:identifier/testResult/:className/:methodName", async (req, res, next) => {
  const identifier = req.params.identifier
  const className = req.params.className
  const methodName = req.params.methodName

  const testResult = await DB.getTestResult(identifier, className, methodName)

  res.send(testResult)
})





app.use(function (err: Error, req: express.Request, res: express.Response, next: express.NextFunction) {
  //console.error(err.stack)
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
