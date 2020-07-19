// import fs, { readdir, readFileSync } from "fs";
// import path from "path";
// import { Utils } from "./utils"
// import { ITestResult, ITestResultContainer } from "../database/models"

// class TestCompare {
//   name: string;
//   SucceededTests: number
//   DisabledTests: number
//   FailedTests: number
//   cStates: number
//   testResults: ITestResult[]
//   statesDiffer: number = 0

//   constructor(name: string, s: number, d: number, f: number, cS: number, testResults: ITestResult[]) {
//     this.name = name;
//     this.DisabledTests = d;
//     this.SucceededTests = s;
//     this.FailedTests = f;
//     this.cStates = cS;
//     this.testResults = testResults
//   }

//   public equals(other: TestCompare): boolean {
//     let equal = true

//     for (let i = 0; i < this.testResults.length; i++) {
//       let testResultEqual = true
//       let r1 = this.testResults[i]
//       let r2 = other.testResults[i]

//       if (r1.TestMethod.ClassName != r2.TestMethod.ClassName) {
//         console.error("something went wrong...", r1, r2)
//         testResultEqual = false
//       }

//       if (r1.States.length != r2.States.length) {
//         testResultEqual = false
//         console.error("Number of handshakes is different in " + r1.TestMethod.ClassName)
//       }

//       for (let j = 0; j < r1.States.length; j++) {
//         let stateR1 = r1.States[j]
//         let stateR2 = r2.States[j]

//         if (stateR1.uuid != stateR2.uuid) {
//           testResultEqual = false
//           console.error("State uuids are not equal", stateR1, stateR2)
//         }

//         if (stateR1.Status != stateR2.Status) {
//           testResultEqual = false
//           this.statesDiffer++
//           console.warn("States are different")
//           console.warn(stateR1, stateR2)
//         }
//       }

//       if (!testResultEqual) {
//         console.warn(`${r1.TestMethod.ClassName.replace("de.rub.nds.tlstest.suite.tests.", "")}.${r1.TestMethod.MethodName} are different (${r1.Status} vs ${r2.Status})`)
//       }

//       equal = equal && testResultEqual
//     }

//     other.statesDiffer = this.statesDiffer
//     return this.FailedTests == other.FailedTests
//       && this.SucceededTests == other.SucceededTests
//       && this.DisabledTests == other.DisabledTests
//       && this.cStates == other.cStates
//       && equal
//   }

//   public pretty(): string {
//     const copy: TestCompare = JSON.parse(JSON.stringify(this))
//     delete copy.testResults
//     return JSON.stringify(copy, null, 4)
//   }
// }


// async function main() {
//   const absolutePath = path.resolve(process.argv[2])

//   let files: string[] = await new Promise<string[]>(resolve => {
//     Utils.walk(absolutePath, (err, results) => {
//       resolve(results)
//     }, f => {
//       return /testResults\.json$/.test(f)
//     })
//   })

//   let implementations = new Set<string>()
//   let fileGroups: string[][] = []
//   for (let f of files) {
//     const folder = path.basename(path.dirname(f))
//     implementations.add(folder.substring(0, folder.length - 6))
//   }

//   for (let f of implementations) {
//     fileGroups.push(files.filter(s => s.indexOf(f) > -1))
//   }

//   const compares: TestCompare[][] = []
//   for (const g of fileGroups) {
//     let a: TestCompare[] = []
//     for (const f of g) {
//       const results: ITestResultContainer = JSON.parse(readFileSync(f).toString("utf-8"))

//       const folder = path.dirname(f).replace(absolutePath, "")
//       let totalCountOfStates = Utils.numberOfStatesForTest(results)
//       let testResults = Utils.getTestResults(results)
//       testResults.sort((a, b) => {
//         const aU = a.TestMethod.ClassName.toUpperCase()
//         const bU = b.TestMethod.ClassName.toUpperCase()
//         if (aU < bU) {
//           return -1;
//         }
//         if (aU > bU) {
//           return 1;
//         }
//         return 0;
//       })

//       for (let result of testResults) {
//         result.States.sort((a, b) => {
//           const aU = a.uuid.toUpperCase()
//           const bU = b.uuid.toUpperCase()
//           if (aU < bU) {
//             return -1;
//           }
//           if (aU > bU) {
//             return 1;
//           }
//           return 0;
//         })
//       }

//       a.push(new TestCompare(folder, results.SucceededTests, results.DisabledTests, results.FailedTests, totalCountOfStates, testResults))
//     }
//     compares.push(a)
//   }


//   let faileds = []
//   for (const i of compares) {
//     for (let j = i.length - 1; j > 0; j--) {
//       for (let k = 0; k < j; k++) {
//         if (!i[k].equals(i[j])) {
//           let failed = `${i[k].name} != ${i[j].name}`
//           faileds.push(failed)
//           console.warn(failed)
//           console.log(i[k].pretty() + "\n" + i[j].pretty());
//           console.log("\n\n")
//         }
//       }
//     }
//   }

//   console.log(faileds.join("\n"))
// }

// main()