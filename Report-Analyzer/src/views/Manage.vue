<template>
  <div>
    <b-container>
      <b-alert v-if="error" variant="danger" show>{{error}}</b-alert>
      <b-form @submit="removeRegex">
        <b-row>
          <b-col>
            <b-form-group
              id="regex-group"
              label="Regex"
              label-for="regex"
              description="Delete all identifiers matching the regex"
            >
              <b-form-input
                id="regex"
                v-model="regex"
                type="text"
                required
                placeholder="Regex"
              ></b-form-input>
            </b-form-group>
          </b-col>
          <b-col>
            <b-button :disabled="!regex" style="margin-top: 32px" type="submit" variant="danger">Delete</b-button>
          </b-col>
        </b-row>
      </b-form>
      <b-row v-for="i in identifiers" :key="i" align-v="center" class="deleteTable">
        <b-col cols="5">{{i}}</b-col>
        <b-col>
          <b-button style="margin: 5px" variant="danger" @click="remove(i)">Delete</b-button>
        </b-col>
      </b-row>
    </b-container>
    
  </div>  
</template>

<script>
export default {
  data() {
    return {
      rawIdentifiers: [],
      error: null,
      regex: null,
    }
  },
  computed: {
    identifiers() {
      if (!this.regex)
        return this.rawIdentifiers
      
      const res = []
      const regex = new RegExp(this.regex)
      for (const i of this.rawIdentifiers) {
        if (regex.test(i)) {
          res.push(i)
        }
      }
      return res
    }
  },
  methods: {
    remove(elem) {
      this.$http.delete(`testReport/${elem}`).then(() => {
        this.error = null
        this.rawIdentifiers.splice(this.rawIdentifiers.indexOf(elem), 1)
      }).catch((e) => {
        this.error = e
        console.error(e)
      })
    },
    removeRegex(e) {
      e.preventDefault()
      this.$http.delete(`testReport/deleteRegex`, {data: {regex: this.regex}}).then(() => {
        this.error = null
        this.init()
      }).catch((e) => {
        this.error = e
        console.error(e)
      })
    },
    init() {
      this.$http.get("testReportIdentifiers").then((resp) => {
        this.rawIdentifiers = resp.data
      }).catch((e) => {
        this.error = e
        console.error(e)
      }) 
    }
  },
  mounted() {
    this.init()
  }
}
</script>

<style lang="scss" scoped>
.deleteTable:nth-child(2n) {
  background-color: #ddd;
}

</style>