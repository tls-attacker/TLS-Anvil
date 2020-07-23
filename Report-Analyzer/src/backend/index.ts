import { spawnSync } from 'child_process';
import cors from 'cors';
import express from "express";
import moment from 'moment';
import DB, { FileType } from './database';
import { ITestResult } from './database/models';
import { UploadReportEndpoint } from './endpoints';
import { BadRequest } from './errors';
import { promises as fsPromises } from 'fs';

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


router.get("/testReportIdentifiers", async (req, res, next) => {
  const results = await DB.testResultContainer.find().select({Identifier: 1}).lean().exec()
  const identifiers = results.map((i) => i.Identifier)
  identifiers.sort()
  res.send(identifiers)
})


router.get("/testReport/:identifier", async (req, res, next) => {
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
  res.send(testReport)
  console.log(`finished in ${new Date().getTime() - start}ms`)
})

router.get("/testReport/:identifier/testResult/:className/:methodName", async (req, res, next) => {
  const identifier = req.params.identifier
  const className = req.params.className
  const methodName = req.params.methodName

  const testResult = await DB.getTestResult(identifier, className, methodName)

  res.send(testResult)
})



async function execProgram(stdin: Buffer, program: string, args: string[]): Promise<Buffer> {
  const env = {...process.env}
  env.COLORTERM="24bit"
  env.TERM="xterm-256color"
  env.COLORFGBG="7;0"
  env.LSCOLORS="Gxfxcxdxbxegedabagacad"
  env.ITERM_PROFILE="Default"
  env.LC_TERMINAL="iTerm2"

  return new Promise((res) => {
    const ret = spawnSync(program, args, {
      input: stdin || 'pipe',
      env: env,
    })
    console.error(ret.stderr.toString('utf-8'))
    res(ret.stdout)
  })
}

router.get("/testReport/:containerId/testResult/:className/:methodName/:uuid/pcap", async (req, res, next) => {
  const containerId = req.params.containerId
  const className = req.params.className
  const methodName = req.params.methodName
  const uuid = req.params.uuid

  const container = await DB.testResultContainer.findOne({_id: containerId}).exec()
  const pcap = DB.downloadFile(FileType.pcap, container.PcapStorageId)
  const keylog = DB.downloadFile(FileType.keylog, container.KeylogfileStorageId)
  const testResult = DB.getTestResult(container.Identifier, className, methodName)

  let startTimestamp: moment.Moment = moment()
  Promise.all([pcap, keylog, testResult]).then((vals) => {
    const pcapFile = vals[0];
    const keylogFile = vals[1];
    const doc: ITestResult = <ITestResult>vals[2];

    const index = (<any>doc.StateIndexMap)[uuid]
    const state = doc.States[index]
    startTimestamp = moment(new Date(state.StartTimestamp))
    startTimestamp.local()

    const promises = []
    promises.push(fsPromises.writeFile('/tmp/k' + container.KeylogfileStorageId, keylogFile))
    promises.push(fsPromises.writeFile('/tmp/p' + container.PcapStorageId, pcapFile))

    return Promise.all(promises).then(() => {
      return state
    })
  })
  .then((state) => {
    return execProgram(null, 'tcpdump', ['-r', '/tmp/p' + container.PcapStorageId, '-w', '-', `tcp port ${state.SrcPort} and tcp port ${state.DstPort}`])
  })
  .then((output) => {
    const timeFilter = `frame.time >= "${startTimestamp.subtract(1, 'seconds').format("YYYY-MM-DD HH:mm:ss.S")}"` +
                    `&& frame.time <= "${startTimestamp.add(10, 'seconds').format("YYYY-MM-DD HH:mm:ss.S")}"`

    if (req.query.download) {
      return fsPromises.writeFile(`/tmp/filtered${container.PcapStorageId}.pcap`, output).then(() => {
        return execProgram(null, 
          'tshark', 
          [
            '-r', `/tmp/filtered${container.PcapStorageId}.pcap`, '-w', '-',
            '-2', '-R', timeFilter
          ]
        )
      })
    }

    return execProgram(output, 
      'tshark', 
      [
        '-n', '-i', '-', 
        '-o', `tls.keylog_file:/tmp/k${container.KeylogfileStorageId}`, '-Y', timeFilter,
        '-o', 'gui.column.format:"Time","%Aut","s","%uS","d","%uD","Protocol","%p","Info","%i"',
        '-T', 'tabs'
      ]
    )
  }).then((output) => {
    if (req.query.download) {
      res.type('application/octet-stream')
      res.send(output)
      return
    }
    res.setHeader('Content-Type', "text/plain")
    res.send(output.toString('utf-8').trim().split('\n').map((i) => `<div class="${classForPacket(i)}">${i.trim()}</div>`).join(''))
  }).catch((e) => {
    return next(new BadRequest(e))
  })
})


router.get('/keylogfile', (req, res, next) => {
  res.type('application/octet-stream')
  DB.downloadKeylogFiles().then((buf) => {
    res.setHeader("Content-Disposition", 'attachment; filename="keylogfile.log"')
    res.send(buf)
  })
})

function classForPacket(packet: string) {
  let css = {
    bgColor: '',
    fgColor: 'black',
    type: 'packet'
  }

  if (["SYN", "FIN"].filter(j => packet.includes(j)).length > 0)
    css.bgColor = 'gray'
  if (packet.includes("HTTP"))
    css.bgColor = "green"
  if (packet.includes("TLS"))
    css.bgColor = 'blue'
  if (packet.includes("RST")) {
    css.bgColor = 'red'
    css.fgColor = 'yellow'
  }
  
  return ['bg-' + css.bgColor, 'fg-' + css.fgColor, css.type].join(' ')
}


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
