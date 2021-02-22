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
      <template v-if="detailsMode == 0">
        <div v-for="k in selectedIdentifiers" :key="k">
          <template v-if="selectedRow && selectedRow[k] && k != 'uuid'">
            <p style="font-weight: bold;">{{ k }}</p>
            <vue-json-pretty
              id="jsonPreview"
              :data="selectedRow[k]"
            >
            </vue-json-pretty>
            <div class="packetViewer"></div>
            <b-button variant="success" class="pcapInlineBtn" @click="downloadPcap(selectedRow[k], k, $event)">Download</b-button>
            <b-button variant="primary" class="pcapInlineBtn" @click="showPcap(selectedRow[k], $event)">Show PCAP</b-button>
          </template>
        </div>
      </template>
      <template v-else-if="detailsMode == 1">
        <template v-if="failureInducingCombinations"></template>
        <vue-json-pretty id="fds" :data="failureInducingCombinations">
        </vue-json-pretty>
        <!-- <div style="height: 50px"></div>
        <div v-for="k in selectedColumn" :key="k.uuid">
          <p style="font-weight: bold;">{{ k.uuid }}</p>
          <vue-json-pretty
            id="jsonPreview"
            :data="k"
          >
          </vue-json-pretty>
          <div class="packetViewer"></div>
          <b-button variant="success" class="pcapInlineBtn" @click="downloadPcap(k, k.Identifier, $event)">Download</b-button>
          <b-button variant="primary" class="pcapInlineBtn" @click="showPcap(k, $event)">Show PCAP</b-button>
        </div> -->
      </template>
      <template v-else-if="detailsMode == 2">
        <vue-json-pretty
          id="jsonPreview"
          :data="selectedCell"
        >
        </vue-json-pretty>
        <div class="packetViewer"></div>
        <b-button variant="success" class="pcapInlineBtn" @click="downloadPcap(selectedCell, selectedCell.Identifier, $event)">Download</b-button>
        <b-button variant="primary" class="pcapInlineBtn show download" @click="showPcap(selectedCell, $event)">Show PCAP</b-button>
      </template>
    </b-modal>

    <b-row>
      <b-col>
        <TableFilter 
          :filterPossibilities="filterOptions"
          v-model="filter"
        ></TableFilter>
      </b-col>
    </b-row>

    <template v-if="testMethod">
      <p style="max-width: 900px">
        <strong>RFC:</strong> {{testMethod.RFC ? testMethod.RFC.number : "" }}, <strong>Section:</strong> {{testMethod.RFC ? testMethod.RFC.Section : ""}}<br>
        <strong>Description:</strong> {{testMethod.Description}}<br>
        <strong>TLS-Version:</strong> {{testMethod.TlsVersion}}<br>
        <strong>Security severity:</strong> {{testMethod.SecuritySeverity}}, <strong>Interoperability severity: </strong> {{testMethod.InteroperabilitySeverity}}<br>
        <strong>Method:</strong> {{testMethod.ClassName}}.{{testMethod.MethodName}}
      </p>
    </template>

    <template v-if="this.selectedIdentifiers.length == 0">
      <h3 style="margin-top: 30px">No State selected</h3>
    </template>
    <template v-else>
      <b-table
        ref="table"
        class="stateTable"
        head-variant="dark"
        :no-border-collapse="false"
        :items="itemProviderProxy"
        :fields="fields"
        :filter="filter"
        sticky-header
        striped
        responsive
        hover
        select-mode="single"
        :tbody-tr-class="rowClass"
        @head-clicked="headClicked"
      >
        <template v-slot:cell(uuid)="data">
          <template v-if="data.value.value && data.value.value.length > 20">
            <span  
              class="uuidRow selectable"
              v-b-popover="{
                placement: 'right',
                customClass: 'uuidPopover',
                trigger: 'hover',
                html: true,
                content: data.value.state.DisplayName
              }"
              @click="uuidColumnClicked(data.item, $event)"
            >{{data.value.value}}</span>
          </template>
          <template v-else>
            <span v-html="data.value"></span>
          </template>
        </template>

        <template v-slot:cell()="data">
          <template v-if="data.value">
            <span v-b-tooltip.hover 
              :title="data.value.AdditionalResultInformation || 'n.a'"
              @click="iconClicked(data.value, data.field.key, $event)"
              class="selectable"
            >
              {{ data.value.statusIcons }}
            </span>
          </template>
        </template>
      </b-table>
    </template>
  </div>
</template>

<script>
import * as stateview from '@/lib/stateview'
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'
import { FilterInputModels } from "@/lib/filter/filterInputModels";
import TableFilter from '@/components/TableFilter'
import { filter } from "@/lib/filter/filter"

export default {
  name: "StateView",
  data() {
    return {
      error: null,
      selectedIdentifiers: [],
      className: null,
      methodName: null,
      testMethod: null,
      guardNavigation: 0,
      filterInputModel: FilterInputModels.states,
      filter: [],
      derivationFilters: null,
      hightlightOption: null, 
      selectedRow: {},
      selectedColumn: [],
      selectedCell: {},
      showDetails: false,
      detailsMode: 0,
      fields: [
        {
          key: "uuid",
          label: "UUID",
          stickyColumn: true,
          thStyle: {width: "640px"},
          tdClass: "stickyColumn"
        }, {
          key: "dummy",
          label: "",
        }
      ]
    }
  },
  computed: {
    filterOptions() {
      const additional = this.derivationFilters ? this.derivationFilters : []
      return [
        ...this.filterInputModel,
        ...additional
      ]
    }
  },
  methods: {
    getStates() {
      const reportIdentifiers = this.testResults.map((i) => i.Identifier)
      const newIdentifiers = this.selectedIdentifiers.filter((i) => reportIdentifiers.indexOf(i) == -1)
      if (newIdentifiers.length == 0) {
        this.$nextTick(() => {
          if (reportIdentifiers.length != this.fields.length - 2) {
            this.fields.splice(1, this.fields.length - 1)
            for (const i of reportIdentifiers) {
              this.fields.push({
                key: i, 
                label: i,
                thStyle: {width: "200px", cursor: "pointer"},
                class: "centered"
              })
            }
            
            this.fields.push({
              key: "dummy",
              label: ""
            })
          }
          this.$refs.table.refresh()
        }) 
        return
      }

      this.fields.splice(this.fields.length - 1, 1)
      for (const i of newIdentifiers) {
        this.fields.push({
          key: i, 
          label: i,
          thStyle: {width: "200px", cursor: "pointer"},
          class: "centered"
        })
      }
      
      this.fields.push({
        key: "dummy",
        label: ""
      })

      const promises = []
      const derivations = new Set()
      const derivationValues = {}
      for (const i of newIdentifiers) {
        const p = this.$http.get(`testReport/${i}/testResult/${this.className}/${this.methodName}`).then((res) => {
          console.log(`finished req ${i}`)
          res.data.Identifier = i
          this.testResults.push(res.data)
          if (!this.testMethod && res.data.TestMethod) {
            this.testMethod = res.data.TestMethod
          }

          if (res.data.States) {
            for (const s of res.data.States) {
              if (!s.DerivationContainer) continue;
              for (const d in s.DerivationContainer) {
                derivations.add(d)
                if (!derivationValues[d]) {
                  derivationValues[d] = new Set()
                }
                derivationValues[d].add(s.DerivationContainer[d])
              }
            }
          }
        }).catch((e) => {
          console.error(e)
        })

        promises.push(p)
      }

      Promise.all(promises).then(() => {
        this.derivationFilters = []
        for (const derivation of derivations) {
          let comparator = ["==", "!=", "contains", "!contains"]
          const values = Array.from(derivationValues[derivation])
          values.sort()
          if (!isNaN(values[0])) {
            comparator = FilterInputModels.Comparator.all
            values.sort((i,j) =>{
              const ni = parseInt(i)
              const nj = parseInt(j)
              if (ni == nj) return 0
              if (ni < nj) return -1
              if (ni > nj) return 1
            })
            
          }

          this.derivationFilters.push({
            key: {
              type: 'derivation',
              mode: derivation
            },
            displayName: derivation,
            type: 'selector',
            values: values,
            comparators: comparator
          })
        }

        this.$refs.table.refresh()
      })
    },
    itemProviderProxy(ctx) {
      console.log("start itemProvider")
      const start = new Date().getTime()
      try {
        const res = stateview.itemProvider(ctx, this.testResults)
        for (let i = 0; i < res.length; i++) {
          const row = res[i]
          if (!filter(this.filterOptions, this.filter, row)) {
            res.splice(i, 1)
            i--;
          }
        }
        console.log(`Finished in ${new Date().getTime() - start}ms (${res.length})`)
        this.currentlyVisibleRows = res
        return res
      } catch(e) {
        console.error("d", e, e.stack)
        return []
      }
    },
    rowClass(item, type) {
      if (type !== "row") return
      return stateview.getRowClass(item, this.hightlightOption)
    },
    uuidColumnClicked(selected, ev) {
      ev.preventDefault()
      ev.stopPropagation()
      ev.stopImmediatePropagation()
      let con = false
      for (const i in selected) {
        if (i === "uuid") continue
        if (selected[i] && Object.keys(selected[i]).length > 1) {
          con = true
          break
        }
      }

      if (!con)
        return

      this.selectedRow = selected
      this.detailsMode = 0
      this.showDetails = true
    },
    iconClicked(data, identifier, ev) {
      ev.preventDefault()
      ev.stopPropagation()
      ev.stopImmediatePropagation()
      this.detailsMode = 2
      this.showPcap(data, null)

      data.Identifier = identifier
      this.selectedCell = data
      this.showDetails = true
    },
    headClicked(key, field) {
      if (key == "uuid") return
      const identifier = field.key
      const result = this.testResults.filter(i => i.Identifier == identifier)[0]
      let states = result.States
      console.log(this.currentlyVisibleRows)
      if (this.currentlyVisibleRows) {
        states = []
        for (const row of this.currentlyVisibleRows) {
          if (row[identifier] && row[identifier].Result)
            states.push(row[identifier])
        }
      }

      states.map((i) => i.Identifier = identifier)
      console.log(result)
      this.failureInducingCombinations = result.FailureInducingCombinations
      this.selectedColumn = states
      this.detailsMode = 1
      this.showDetails = true
    },
    updateParameters(route) {
      this.error = null
      if (route.query.selected) {
        this.selectedIdentifiers = route.query.selected.split(',')
      }
      if (route.query.className) {
        this.className = route.query.className
      }
      if (route.query.methodName) {
        this.methodName = route.query.methodName
      }

      this.$nextTick(() => {
        this.getStates()
      })
    },
    checkCache(selected, className, methodName) {
      let sameSelection = true
      for (let i = 0; i < selected.length; i++) {
        if (selected[i] !== this.selectedIdentifiers[i]) {
          sameSelection = false
        }
      }

      if (!sameSelection || className !== this.className || methodName !== this.methodName) {
        this.testResults = []
        this.testMethod = null
        this.derivationFilters = null
        if (this.fields.length > 2) {
          this.fields.splice(1, this.fields.length - 2)
        }
        this.$nextTick(() => {
          this.$refs.table.refresh()
        })
      } 
    },

    async showPcap(selectedCell, ev) {
      let target = null
      if (ev) {
        ev.target.innerHTML = 'Loading...'
        ev.target.disabled = true
        target = ev.target.previousSibling.previousSibling
      } else {
        while (!document.querySelector(".packetViewer")) {
          await new Promise((res) => setTimeout(() => res(), 500));
        }

        const t = document.querySelector(".pcapInlineBtn.download")
        if (t) {
          t.innerHTML = "Loading..."
          t.disabled = true
        }
      }

      this.$http.get(`/testReport/${selectedCell.ContainerId}/testResult/${this.className}/${this.methodName}/${selectedCell.uuid}/pcap`).then(async (res) => {

        while (!document.querySelector(".packetViewer") && !ev) {
          await new Promise((res) => setTimeout(() => res(), 500));
        }

        if (ev) {
          ev.target.hidden = true
        } else {
          target = document.querySelector(".packetViewer")
          document.querySelector(".pcapInlineBtn.download").hidden = true
        }        

        target.innerHTML = res.data
      }).catch(() => {
        if (ev) {
          ev.target.innerHTML = "Error..."
          ev.target.disabled = false
        }
      })
    },
    
    downloadPcap(selectedCell, identifier, ev) {
      ev.target.innerHTML = 'Loading...'
      ev.target.disabled = true

      this.$http.get(`/testReport/${selectedCell.ContainerId}/testResult/${this.className}/${this.methodName}/${selectedCell.uuid}/pcap?download=1`, {responseType: 'blob'}).then((res) => {
        const url = URL.createObjectURL(res.data)
        const link = document.createElement('a')
        link.href = url
        link.download = `${identifier}_${this.methodName}_${this.className.replace('de.rub.nds.tlstest.suite.tests.', '')}_${selectedCell.uuid}.pcap`
        link.click()
      }).then(() => {
        ev.target.innerHTML = "Download"
        ev.target.disabled = false
      }).catch(e => {
        ev.target.innerHTML = "Error..."
        ev.target.disabled = false
        console.error(e)
      })
    }
  },
  created() {
    console.log("created")
    this.testResults = []
  },
  beforeRouteUpdate(to, from, next) {
    if (this.guardNavigation > 0) {
      this.guardNavigation -= 1
      next()
      return
    }

    console.log("beforeRouteUpdate")
      
    const selected = to.query.selected ? to.query.selected.split(',') : []
    const className = to.query.className
    const methodName = to.query.methodName
    this.checkCache(selected, className, methodName)
    this.updateParameters(to)

    next()
  },
  activated() {
    const selected = this.$route.query.selected ? this.$route.query.selected.split(',') : []
    const className = this.$route.query.className
    const methodName = this.$route.query.methodName
    this.checkCache(selected, className, methodName)
    this.updateParameters(this.$route)
  },
  components: {
    VueJsonPretty,
    TableFilter
  }
};
</script>

<style lang="scss">
.stateTable {
  margin-top: 30px;
  max-height: 100vh;
  margin-bottom: 0;
}

.differentStatus {
  background-color: rgb(255, 187, 142) !important;
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

.uuidRow {
  font-family: monospace;
}

#jsonPreview {
  background-color: rgb(233, 233, 233);
  padding: 9px;
  border: 1px solid rgb(97, 97, 97);
  border-radius: 3px;
  word-break: break-word;
}

.pcapInlineBtn {
  margin: 0px 10px 40px 0
}

.uuidPopover {
  max-width: 100%;
  width: auto !important;
}

.packetViewer {
  font-family: monospace;
  overflow-x: auto;
  font-size: 12px;
  background-color: #f2f2f2;
  margin: 6px 0 6px 0;

  .packetWrapper {
    display: inline-block;
    white-space: pre;
    min-width: 100%;
  }

  .packet {
    padding: 0 8px
  }

  .fg-black {
    color: black
  }

  .fg-yellow {
    color: #fffc9c
  }

  .bg-green {
    background-color: #e4ffc7;
  }

  .bg-blue {
    background: #e7e6ff;
  }

  .bg-red {
    background-color: #a40000;
  }

  .bg-gray {
    background-color: #a0a0a0;
  }
}
</style>
