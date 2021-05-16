import cors from 'cors';
import { KeylogFileEndpoint } from './endpoints/KeylogFileEndpoint';
import express, { NextFunction, Request, Response, Router } from "express";
import DB, { FileType } from './database';
import { UploadReportEndpoint } from './endpoints';
import { BadRequest, InternalServerError } from './errors';
import { PcapEndpoint } from './endpoints/PcapEndpoint';
import { TestReportEndpoint } from './endpoints/TestReportEndpoint';
import { TestResultEndpoint } from './endpoints/TestResultEndpoint';

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
new TestReportEndpoint.Controller(router)
new TestResultEndpoint.Controller(router)


app.use(function (err: Error, req: Request, res: Response, next: NextFunction) {
  //console.error(err.stack)
  if (res.headersSent) {
    return next(err)
  }

  if (err instanceof BadRequest) {
    res.status(400)
    res.send({success: false, error: err.message})
    return
  } else if (err instanceof InternalServerError) {
    res.status(500)
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
