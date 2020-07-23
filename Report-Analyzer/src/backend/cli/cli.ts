import fs, { readdir, readFileSync, existsSync } from "fs";
import path, { basename, dirname } from "path";
import {Utils} from './utils'
import { ITestResult, ITestResultContainer } from "../database/models"
import moment from 'moment';
import { UploadReportEndpoint } from '../endpoints';
import axios from 'axios'

async function main() {
  const absolutePath = path.resolve(process.argv[2])

  let files: string[] = await new Promise<string[]>(resolve => {
    Utils.walk(absolutePath, (err, results) => {
      resolve(results)
    }, f => {
      return /testResults\.json$/.test(f)
    })
  })

  for (const f of files) {
    const dir = path.dirname(f)
    const pcap = path.join(dir, 'dump.pcap')
    const keyfile = path.join(dir, 'keyfile.log')
    const results = f

    if (!existsSync(results) || !existsSync(keyfile) || !existsSync(pcap)) {
      console.error("Files missing in folder " + dir)
      continue
    }

    const pcapContent = readFileSync(pcap).toString('base64')
    const keyfileContent = readFileSync(keyfile).toString('base64')
    const resultsContent: ITestResultContainer = JSON.parse(readFileSync(results, 'utf-8'))

    resultsContent.Identifier = basename(dir)
    resultsContent.Date = moment(basename(dirname(dir)), "DD-MM-YY_HHmmss").toDate()
    resultsContent.ShortIdentifier = basename(dir).replace('client', 'c').replace('server', 's')
    resultsContent.ShortIdentifier = resultsContent.ShortIdentifier.slice(0, resultsContent.ShortIdentifier.length - 6)

    const uploadData: UploadReportEndpoint.IBody = {
      keylog: keyfileContent,
      pcapDump: pcapContent,
      testReport: resultsContent
    }

    
    await new Promise((res) => {
      axios.post('http://localhost:5000/api/v1/uploadReport', uploadData, {
        maxContentLength: 500000000
      }).then(() => {
        console.log('Uploaded ' + resultsContent.Identifier)
        res()
      }).catch((e: Error) => {
        e.stack = null
        console.error("Upload failed " + resultsContent.Identifier, e.message)
        res()
      })
    })
  }


}

main()