<template>
  <div class="upload">
    <h1 style="text-align: center">Upload</h1>

    <b-form-file
      v-model="file"
      accept="application/json"
      size="lg"
      :state="Boolean(file)"
      placeholder="Choose a file or drop it here..."
      drop-placeholder="Drop file here..."
    ></b-form-file>

    <InputForm
      name="identifier"
      placeholder="Identifier"
      v-model="identifier"
      style="margin-top: 20px"
      :required="false"
    >
    </InputForm>

    <div style="margin-top: -14px">
      <b-button :disabled="!Boolean(file)" variant="success" @click="upload">Upload</b-button>
      <b-button :disabled="!Boolean(file)" variant="danger" @click="reset">Clear File</b-button>
      <span style="color: red" v-if="error != null">{{ error }}</span>
    </div>

    <pre id="jsonPreview" v-if="cleanedJson != null">{{ cleanedJson }}</pre>
  </div>
</template>

<script>
import InputForm from "@/components/InputForm.vue";

export default {
  data: () => {
    return {
      file: null,
      error: null,
      cleanedJson: null,
      rawJSON: null,
      identifier: null,
    }
  },
  watch: {
    file: function (n) {
      console.log("changed", n)
      if (n) {
        const fileReader = new FileReader()
        fileReader.onload = () => {
          try {
            const input = JSON.parse(fileReader.result)
            this.rawJSON = JSON.parse(fileReader.result)
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
    }
  },
  methods: {
    reset() {
      this.file = null
      this.content = null
      this.cleanedJson = null
      this.identifier = null
      this.error = null
    },
    upload() {
      this.rawJSON.Identifier = this.identifier
      this.$http.post("/uploadReport", this.rawJSON).then(() => {
        this.$router.push("Analyzer")
      }).catch((e) => {
        this.error = `${e}`
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
