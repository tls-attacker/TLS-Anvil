<template>
  <div class="analyzer">
    <b-alert v-if="error" variant="danger" show>{{error}}</b-alert>
    <b-modal id="modal-xl" 
      v-model="showDetails" 
      scrollable 
      size="xl" 
      title="Details"
      ok-only
    >
      <vue-json-pretty
        id="jsonPreview"
        :data="modalContent"
      >
      </vue-json-pretty>
    </b-modal>

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
      <b-col cols="auto">
        <b-button variant="primary"
          @click="downloadKeylogfile($event)"
        >Download Keylogfile</b-button>
      </b-col>
    </b-row>
    <b-row style="margin-top: 20px">
      <b-col cols="2">
        <b-form-group label="Hightlight rows">
          <b-form-radio-group
            v-model="hightlightOption"
            :options="options.hightlight"
            name="radios-stacked"
            stacked
          ></b-form-radio-group>
        </b-form-group>
        <b-form-group label="Filter differences:">
          <b-form-checkbox-group
            id="properties"
            v-model="filter.properties"
            :options="options.difference"
            name="properties"
            stacked
          ></b-form-checkbox-group>
        </b-form-group>
      </b-col>
      <b-col cols="2">
        <b-form-group label="Filter security severities:">
          <b-form-checkbox-group
            id="security"
            v-model="filter.severity.security"
            :options="options.severity"
            name="security"
            stacked
          ></b-form-checkbox-group>
        </b-form-group>
      </b-col>
      <b-col cols="3">
        <b-form-group label="Filter interoperability severities:">
          <b-form-checkbox-group
            id="interoperability"
            v-model="filter.severity.interoperability"
            :options="options.severity"
            name="interoperability"
            stacked
          ></b-form-checkbox-group>
        </b-form-group>
      </b-col>
      <b-col cols="3">
        <b-form-group label="Filter test results:">
          <b-form-checkbox-group
            id="status"
            v-model="filter.status"
            :options="options.status"
            name="status"
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
        id="table"
      >
        <template v-slot:cell(testcase)="data">
          <template v-if="data.item.testcase.value">
            <span 
              v-html="data.item.testcase.value" 
              @click="clickedTestCase(data.item.testcase.TestMethod, $event)"
            ></span>
          </template>
          <template v-else>
            <span v-html="data.item.testcase"></span>
          </template>
        </template>
        <template v-slot:cell()="data">
          <template v-if="data.value.States">
            <span 
              v-b-tooltip="{
                hover: true,
                html: true,
                title: [data.value.FailedReason, `${data.value.States.length} states`].filter(i => i != null).join('<br/>')
              }"
            >{{ data.value.statusIcons }}</span>
          </template>
          <template v-else>
            <span>{{ data.value.statusIcons }}</span>
          </template>
        </template>
        <template v-slot:head()="data">
          <template v-if="data.column != 'testcase' && reportsMetadata[data.column]">
            <div v-b-tooltip.hover
            :title="reportsMetadata[data.column].Date || ''"
            >{{ reportsMetadata[data.column].ShortIdentifier || reportsMetadata[data.column].Identifier }}</div>
          </template>
          <template v-else>
            <div>{{ data.label }}</div>
          </template>
        </template>
      </b-table>
    </template>
  </div>
</template>

<script>
import { allSeverityLevels, allStatus } from '@/lib/const'
import * as analyzer from '@/lib/analyzer'
import VueJsonPretty from 'vue-json-pretty'

let reports = []
export default {
  name: "Analyzer",
  data() {
    return {
      error: null,
      selectedIdentifiers: [],
      addedScrollListener: false,
      scrollPosition: 0,
      availableIdentifiers: [],
      reportsMetadata: {},
      currentSelection: "",
      regex: "",
      guardNavigation: 0,
      options: {
        severity: allSeverityLevels,
        status: allStatus,
        hightlight: analyzer.hightlightOptions,
        difference: analyzer.differenceFilterOptions
      },
      hightlightOption: null, 
      filter: analyzer.filterObj,
      showDetails: false,
      modalContent: null,
      fields: [
        {
          key: "testcase",
          label: "Testcase",
          stickyColumn: true,
          thStyle: { width: "590px" },
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
        if (this.fields.length - 2 != reportIdentifiers.length) {
          this.fields.splice(1, this.fields.length - 1)
          for (const i of reportIdentifiers) {
            this.fields.push({
              key: i, 
              label: i,
              thStyle: { width: "200px" },
              class: "centered"
            })
          }
          this.fields.push({
            key: "dummy",
            label: ""
          })
        }

        this.$nextTick(() => {
          this.$refs.table.refresh()
        })
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
          key: i, 
          label: i,
          thStyle: { width: "200px" },
          class: "centered"
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
          console.log(`finished req ${i}`)
          this.reports.push(res.data)
          this.reportsMetadata[i] = {
            Date: res.data.Date,
            ShortIdentifier: res.data.ShortIdentifier,
            Identifier: res.data.Identifier
          }
        }).catch((e) => {
          console.error(e)
        })

        promises.push(p)
      }

      Promise.all(promises).then(() => {
        this.$refs.table.refresh()
        if (!this.addedScrollListener) {
          this.addedScrollListener = true
          document.getElementById('table').parentElement.addEventListener('scroll', (e) => {
            this.scrollPosition = e.target.scrollTop
          })
        }
      })
    },
    itemProviderProxy(ctx) {
      console.log("start itemProvider")
      const start = new Date().getTime()
      const res = analyzer.itemProvider(ctx, this.reports)
      console.log(`Finished in ${new Date().getTime() - start}ms (${res.length})`)
      console.log(res)

      return res
    },
    rowClass(item, type) {
      if (type !== "row") return
      if (!item) return

      if (Object.keys(item).length == 1) {
        return ["newClass", "stickyColumn", "notSelectable"]
      }

      return analyzer.getRowClass(item, this.hightlightOption)
    },
    onRowSelected(items) {
      this.$refs.table.clearSelected()
      const selected = items[0]
      let selectedRow = null
      let con = false
      for (const i in selected) {
        if (i === "testcase") continue
        if (selected[i] && selected[i].States && selected[i].States.length > 0) {
          con = true
          selectedRow = selected[i]
          break
        }
      }

      if (!con)
        return

      this.$router.push({
        name: "states", 
        query: {
          selected: this.selectedIdentifiers.join(','), 
          className: selectedRow.TestMethod.ClassName, 
          methodName: selectedRow.TestMethod.MethodName
        }
      })

    },
    clickedTestCase(testMethod, ev) {
      if (!testMethod) return
      ev.preventDefault()
      ev.stopPropagation()
      ev.stopImmediatePropagation()
      this.modalContent = testMethod
      this.showDetails = true
    },
    downloadKeylogfile(ev) {
      const store = ev.target.innerHTML
      ev.target.innerHTML = 'Loading...'
      ev.target.disabled = true

      this.$http.get(`/keylogfile`, {responseType: 'blob'}).then((res) => {
        const url = URL.createObjectURL(res.data)
        const link = document.createElement('a')
        link.href = url
        link.download = `keylogfile.log`
        link.click()
      }).then(() => {
        ev.target.innerHTML = store
        ev.target.disabled = false
      }).catch(e => {
        ev.target.innerHTML = "Error..."
        ev.target.disabled = false
        console.error(e)
      })
    }
  },
  created() {
    this.reports = reports
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
  activated() {
    const scrollContainer = document.getElementById('table')?.parentElement || null
    console.log('activated')
    if (this.scrollPosition > 0 && scrollContainer) {
      console.log('scroll')
      scrollContainer.scrollTo(0, this.scrollPosition)
    }
  },
  beforeRouteUpdate(to, from, next) {
    if (this.guardNavigation > 0) {
      this.guardNavigation -= 1
      next()
      return
    }

    console.log("beforeRouteUpdate")
      
    reports = []
    this.reports = reports
    
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
    VueJsonPretty
  }
};
</script>

<style lang="scss">
.resultTable {
  margin-top: 30px;
  max-height: 100vh;
  margin-bottom: 0;
}

.highlight {
  background-color: rgb(255, 187, 142) !important;
}

.newClass {
  font-weight: 900;
}

.stickyColumn {
  color: #fff !important;
  background-color: #343a40 !important;
  border: 0 !important;
}

.notSelectable {
  cursor: default !important;
}

.centered {
  text-align: center;
}

thead th {
  vertical-align: middle !important;
}
</style>
