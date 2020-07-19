<template>
  <div class="analyzer">
    <b-alert v-if="error" variant="danger" show>{{error}}</b-alert>

    <b-row>
      <b-col cols="3">
        <b-form-select
          :options="availableIdentifiers"
          v-model="currentSelection"
        >
        </b-form-select>
      </b-col>
      <b-col cols="auto">
        <b-button variant="success" style="margin-left: 10px" :disabled="!this.currentSelection || this.selectedIdentifiers.indexOf(this.currentSelection) != -1" @click="addSelectionToDashbard" v-model="regex">Add</b-button>
      </b-col>
      <b-col cols="3">
        <b-form-input v-model="regex" placeholder="Regex"></b-form-input>
      </b-col>
      <b-col cols="auto">
        <b-button 
          variant="success" 
          style="margin-left: 10px" 
          @click="addRegexToDashbard" 
          :disabled="!regex">
        Add
        </b-button>
      </b-col>
    </b-row>
    <b-row style="margin-top: 20px">
      <b-col cols="2">
        <b-form-checkbox
          v-model="options.highlightDifferentStatus"
          name="difference"
        >
          Highlight different results
        </b-form-checkbox>
      </b-col>
      <b-col cols="2">
        <b-form-group label="Filter security severities:">
          <b-form-checkbox-group
            id="security"
            v-model="filter.security"
            :options="options"
            name="security"
            stacked
          ></b-form-checkbox-group>
        </b-form-group>
      </b-col>
      <b-col cols="3">
        <b-form-group label="Filter interoperability severities:">
          <b-form-checkbox-group
            id="interoperability"
            v-model="filter.interoperability"
            :options="options"
            name="interoperability"
            stacked
          ></b-form-checkbox-group>
        </b-form-group>
      </b-col>
    </b-row>


    <template v-if="this.selectedIdentifiers.length == 0">
      <h3 style="margin-top: 30px">Please select at least one report!</h3>
    </template>
    <template v-else>
      <b-table
        ref="table"
        class="resultTable"
        head-variant="dark"
        :no-border-collapse="false"
        :items="itemProviderProxy"
        :filter="filter"
        :fields="fields"
        sticky-header
        striped
        responsive
        hover
        selectable
        select-mode="single"
        :tbody-tr-class="rowClass"
        @row-selected="onRowSelected"
      >
        <template v-slot:cell(testcase)="data">
          <span v-html="data.value"></span>
        </template>
      </b-table>
    </template>
  </div>
</template>

<script>
import { itemProvider, getRowClass, filterObj, allSeverityLevels } from '@/lib'

export default {
  name: "Analyzer",
  data() {
    return {
      error: null,
      selectedIdentifiers: [],
      availableIdentifiers: [],
      currentSelection: "",
      regex: "",
      guardNavigation: 0,
      reports: [],
      options: allSeverityLevels,
      filter: filterObj,
      fields: [
        {
          key: "testcase",
          label: "Testcase",
          stickyColumn: true,
          thStyle: {width: "480px"},
          tdClass: "stickyColumn"
        }, {
          key: "dummy",
          label: "",
        }
      ]
    }
  },
  methods: {
    addSelectionToDashbard() {
      if (this.currentSelection) {
        if (this.selectedIdentifiers.indexOf(this.currentSelection) == -1) {
          this.selectedIdentifiers.push(this.currentSelection)
          this.getReports()
        }
      }
    },
    addRegexToDashbard() {
      if (this.regex) {
        for (const i of this.availableIdentifiers) {
          if (new RegExp(this.regex).test(i) && this.selectedIdentifiers.indexOf(i) == -1) {
            this.selectedIdentifiers.push(i)
          }
        }
        this.getReports()
      }
    },
    getReports() {
      const reportIdentifiers = this.reports.map((i) => i.Identifier)
      const newIdentifiers = this.selectedIdentifiers.filter((i) => reportIdentifiers.indexOf(i) == -1)
      if (newIdentifiers.length == 0) {
        return
      }

      let routeSelected = this.$route.query.selected
      let shouldReplaceRoute = false
      if (routeSelected) {
        routeSelected = routeSelected.split(",")
      } else {
        routeSelected = []
      }

      this.fields.splice(this.fields.length - 1, 1)
      for (const i of newIdentifiers) {
        this.fields.push({
          key: i + ".statusIcons", 
          label: i,
          thStyle: {width: "200px"}
        })

        if (routeSelected.indexOf(i) == -1) {
          routeSelected.push(i)
          shouldReplaceRoute = true
        }
      }
      
      this.fields.push({
        key: "dummy",
        label: ""
      })
      
      if (shouldReplaceRoute) {
        this.guardNavigation += 1
        this.$router.replace({name: "Analyzer", query: { selected: routeSelected.join(',') }})
      }

      const promises = []
      for (const i of newIdentifiers) {
        const p = this.$http.get(`testReport/${i}`).then((res) => {
          this.reports.push(res.data)
        }).catch((e) => {
          console.error(e)
        })

        promises.push(p)
      }

      Promise.all(promises).then(() => {
        this.$refs.table.refresh()
      })
    },
    itemProviderProxy(ctx) {
      return itemProvider(ctx, this.reports)
    },
    rowClass(item, type) {
      if (type !== "row") return
      if (!item) return

      if (Object.keys(item).length == 1) {
        return ["newClass", "stickyColumn"]
      }

      return getRowClass(item, this.options)
    },
    onRowSelected(items) {
      this.$refs.table.clearSelected()
      const selected = items[0]
      let con = false
      for (const i in selected) {
        if (i === "testcase") continue
        if (selected[i] && selected[i].States && selected[i].States.length > 0) {
          con = true
          break
        }
      }

      if (!con)
        return

      console.log(selected)
    }
  },
  mounted() {
    this.$http.get("testReportIdentifiers").then((resp) => {
      this.availableIdentifiers = resp.data
      this.error = null
      if (this.$route.query.selected) {
        const routeSelected = this.$route.query.selected.split(',')
        for (const i of routeSelected) {
          if (this.availableIdentifiers.indexOf(i) > -1 && this.selectedIdentifiers.indexOf(i) == -1) {
            this.selectedIdentifiers.push(i)
          }
        }
        this.getReports()
      }
    }).catch((e) => {
      console.error(e)
      this.error = e
    })
  },
  beforeRouteUpdate(to, from, next) {
    if (this.guardNavigation > 0) {
      this.guardNavigation -= 1
      next()
      return
    }

    console.log("beforeRouteUpdate")
      
    this.reports = []
    if (this.fields.length > 2) {
      this.fields.splice(1, this.fields.length - 2)
    } 
    
    let routeSelected = to.query.selected
    if (!routeSelected) {
      routeSelected = []
      this.selectedIdentifiers = []
      this.$refs.table.refresh()
    } else {
      routeSelected = routeSelected.split(",")
      this.selectedIdentifiers = routeSelected
    }

    this.getReports()

    next()
  },
  components: {
    
  }
};
</script>

<style lang="scss">
.resultTable {
  margin-top: 30px;
  max-height: calc(100vh - 160px);
  margin-bottom: 0;
}

.differentStatus {
  background-color: rgb(255, 187, 142) !important;
}

.newClass {
  font-weight: 1000;
}

.stickyColumn {
  color: #fff !important;
  background-color: #343a40 !important;
}

.notSelectable {
  cursor: default !important;
}

thead th {
  vertical-align: middle !important;
}
</style>
