<template>
  <div class="upload">
    <h1 style="text-align: center">Upload</h1>

    <b-form @submit="upload" @reset="reset">
      <b-form-group label="Test Result JSON File" label-for="testReportFile">
        <b-form-file
          id="testReportFile"
          v-model="testReportFile"
          accept="application/json"
          size="lg"
          :state="Boolean(testReportFile)"
          placeholder="Choose a file or drop it here..."
          drop-placeholder="Drop file here..."
        ></b-form-file>
      </b-form-group>

      <b-form-group label="PCAP File" label-for="pcapDumpFile">
        <b-form-file
          id="pcapDumpFile"
          v-model="pcapDumpFile"
          accept=".pcap, .pcapng"
          size="lg"
          :state="Boolean(pcapDumpFile)"
          placeholder="Choose a file or drop it here..."
          drop-placeholder="Drop file here..."
        ></b-form-file>
      </b-form-group>

      <b-form-group label="Keylog File" label-for="keylogfile">
        <b-form-file
          id="keylogfile"
          v-model="keylogFile"
          accept=".log"
          size="lg"
          :state="Boolean(keylogFile)"
          placeholder="Choose a file or drop it here..."
          drop-placeholder="Drop file here..."
        ></b-form-file>
      </b-form-group>
      

      <InputForm
        name="identifier"
        placeholder="Identifier"
        v-model="identifier"
        style="margin-top: 20px"
        :required="false"
      >
      </InputForm>

      <div style="margin-top: -14px">
        <b-button :disabled="!Boolean(keylogFile) || !Boolean(testReportFile) || !Boolean(pcapDumpFile) || loading" 
          variant="success" 
          type="submit"
        >
          <template v-if="!loading">Upload</template>
          <template v-else>
            <b-spinner small></b-spinner>
            <span class="">Loading...</span>
          </template>
        </b-button>
        <b-button :disabled="!Boolean(keylogFile) && !Boolean(testReportFile) && !Boolean(pcapDumpFile) && !identifier || loading" 
          variant="danger" 
          type="reset">
          Reset
        </b-button>
        <span style="color: red" v-if="error != null">{{ error }}</span>
      </div>
    </b-form>
    

    <pre id="jsonPreview" v-if="cleanedJson != null">{{ cleanedJson }}</pre>
  </div>
</template>

<script>
import InputForm from "@/components/InputForm.vue";

export default {
  data: () => {
    return {
      testReportFile: null,
      pcapDumpFile: null,
      keylogFile: null,
      error: null,
      cleanedJson: null,
      loading: false,
      uploadData: {
        testReport: null,
        pcapDump: null,
        keylog: null
      },
      identifier: null,
    }
  },
  watch: {
    testReportFile: function (n) {
      console.log("changed", n)
      if (!n) {
        return
      }

      const fileReader = new FileReader()
      fileReader.onload = () => {
        try {
          const input = JSON.parse(fileReader.result)
          this.uploadData.testReport = JSON.parse(fileReader.result)
          delete input.TestClasses
          delete input.TestResults
          if (input.Identifier) {
            this.identifier = input.Identifier
          }
          this.cleanedJson = JSON.stringify(input, null, 2)
        } 
        catch {
          fileReader.onerror("JSON could not be parsed")
        } 
      }
      fileReader.onerror = (e) => {
        this.error = `Error: ${e}`
      }
      fileReader.onabort = fileReader.onerror

      fileReader.readAsText(n)
    }
  },
  methods: {
    reset(ev) {
      ev.preventDefault()
      this.testReportFile = null
      this.content = null
      this.cleanedJson = null
      this.identifier = null
      this.error = null
    },
    async readFile(file) {
      return new Promise((res, rej) => {
        if (!file) {
          rej("missing file")
          return
        }

        const fileReader = new FileReader()
        fileReader.onload = () => {
          try {
            res(fileReader.result.split(',')[1])
          }
          catch {
            fileReader.onerror("File could not be read")
          } 
        }
        fileReader.onerror = (e) => {
          this.error = `Error: ${e}`
          rej(e)
          return
        }
        fileReader.onabort = fileReader.onerror
        fileReader.readAsDataURL(file)
      })
    },
    async upload(ev) {
      ev.preventDefault()
      this.error = null
      this.uploadData.testReport.Identifier = this.identifier
      this.loading = true
      const promises = [this.readFile(this.pcapDumpFile), this.readFile(this.keylogFile)]
      Promise.all(promises).then((results) => {
        this.uploadData.pcapDump = results[0]
        this.uploadData.keylog = results[1]
        return this.$http.post("/uploadReport", this.uploadData)
      }).then(() => {
        this.loading = false
        this.$router.push({name: "Analyzer"})
      }).catch((e) => {
        this.error = `${e}`
        this.loading = false
        if (e.response.data.error) {
          this.error = e.response.data.error
        }
      })
    }
  },
  components: {
    InputForm
  }
}
</script>

<style lang="scss" scoped>
.upload {
  max-width: 768px;
  margin: 0 auto;
  padding: 0 10px;

  @media(max-width: 768px) {
    max-width: 100%;
    padding: 0;
    margin: 0
  }
}

#jsonPreview {
  margin-top:30px;
  background-color: rgb(233, 233, 233);
  padding: 9px;
  border: 1px solid rgb(97, 97, 97);
  border-radius: 3px;
}
</style>
