<template>
  <div class="analyzer">
    <b-alert v-if="error" variant="danger" show>{{error}}</b-alert>

    <!-- Detail Modal View -->
    <b-modal id="modal-xl" 
      v-model="showDetails" 
      scrollable 
      size="xl" 
      title="Details"
      ok-only
    >
      <template v-if="detailsMode == 0">
        <div v-for="k in selectedIdentifiers" :key="k">
          <template v-if="selectedRow && selectedRow[k] && selectedRow[k].data && k != 'rowHead'">
            <p style="font-weight: bold;">{{ k }}</p>
            <vue-json-pretty
              id="jsonPreview"
              :data="selectedRow[k].data"
            >
            </vue-json-pretty>
            <div class="packetViewer"></div>
            <b-button variant="success" class="pcapInlineBtn" @click="downloadPcap(selectedRow[k].data, k, $event)">Download</b-button>
            <b-button variant="primary" class="pcapInlineBtn" @click="showPcap(selectedRow[k].data, $event)">Show PCAP</b-button>
          </template>
        </div>
      </template>
      <template v-else-if="detailsMode == 1">
        <template v-if="selectedCell"></template>
        <vue-json-pretty id="jsonPreview" :data="selectedCell">
        </vue-json-pretty>
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

    <!-- Edit Modal View -->
    <b-modal id="edit-modal"
      v-model="showEditPanel" 
      scrollable
      size="xl"
      title="Edit panel to change the test result"
      :ok-disabled="!editPanelData.validated"
      ok-variant="success"
      @ok="submitEdit()"
    >
      <EditPanel
        v-model="editPanelData"
      ></EditPanel>
    </b-modal>

    <!-- TOP of the page -->
    <template v-if="testMethod">
      <p style="max-width: 900px">
        <template v-if="testMethod.RFC">
          <strong>RFC:</strong> {{testMethod.RFC.Number}}, <strong>Section:</strong> {{testMethod.RFC.Section}}<br>
        </template>
        <strong>Description:</strong> {{testMethod.Description}}<br>
        <strong>TLS-Version:</strong> {{testMethod.TlsVersion}}<br>
        <strong>Method:</strong> <span class="monospace">{{testMethod.ClassName.replace("de.rub.nds.tlstest.suite.tests.", "")}}.{{testMethod.MethodName}}</span><br>
        <strong>Severity Levels:</strong>
        <vue-json-pretty
          id="jsonPreview"
          :data="testMethod.data"
        >
        </vue-json-pretty>
      </p>
    </template>
    <template v-else>
      <div style="height: 280px;"></div>
    </template>

    <!-- Filter -->
    <b-row>
      <b-col>
        <TableFilter 
          :filterPossibilities="filterOptions"
          v-model="filter"
          @filterChanged="filterChanged()"
        ></TableFilter>
      </b-col>
    </b-row>

    <!-- Edit Button -->
    <b-row>
      <b-col align-h="end">
        <b-button variant="primary" style="float:right" @click="showEditPanel = !showEditPanel">Edit</b-button>
      </b-col>
    </b-row>

    <!-- Table -->
    <b-overlay :show="showOverlay" no-fade rounded="sm">
      <div id="table" class="stateTable">
        <!-- rendered by the server as HTML -->
      </div>
    </b-overlay>
  </div>
</template>

<script>
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'
import { FilterInputModels } from "@/lib/filter/filterInputModels";
import TableFilter from '@/components/TableFilter'
import EditPanel from '@/components/EditPanel'
import { filter } from "@/lib/filter/filter2"

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
      additionalResultInformationFilter: null,
      additionalTestInformationFilter: null,
      hightlightOption: null, 
      selectedRow: {},
      selectedCell: {},
      showDetails: false,
      showEditPanel: false,
      editPanelData: {},
      detailsMode: 0,
      showOverlay: false
      /* non-reactive data
      tableData: []
      resultData: {}
      */
    }
  },
  computed: {
    filterOptions() {
      const derivationFilters = this.derivationFilters ? this.derivationFilters : []
      const result = [
        ...this.filterInputModel,
      ]

      if (this.additionalResultInformationFilter) {
        result.push(this.additionalResultInformationFilter)
      }
      if (this.additionalTestInformationFilter) {
        result.push(this.additionalTestInformationFilter)
      }

      result.push(...derivationFilters)

      return result
    }
  },
  methods: {
    async getStates() {
      this.showOverlay = true
      await this.$http.get(`testResult/${this.className}/${this.methodName}`, {
        params: {
          identifiers: this.selectedIdentifiers,
        }
      }).then((res) => {
        this.tableData = res.data.tableData
        this.resultData = res.data.resultData

        const d = this.resultData[this.selectedIdentifiers[0]]
        this.testMethod = d.TestMethod
        this.testMethod.data = {}
        const score = d.Score
        for (const key of Object.keys(score)) {
          this.testMethod.data[key] = score[key].SeverityLevel
        }

        this.derivationFilters = []
        const filterData = res.data.filterData
        for (const derivation of filterData.derivationsSet) {
          let comparator = ["==", "!=", "contains", "!contains"]
          const values = Array.from(filterData.derivationValues[derivation])
          if (!isNaN(values[0])) {
            comparator = FilterInputModels.Comparator.all
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

        if (filterData.additionalResultInformationSet.size > 0) {
          const comparator = ["==", "!="]
          const values = Array.from(filterData.additionalResultInformationSet)

          this.additionalResultInformationFilter = {
            key: {
              type: 'additionalResultInformation',
            },
            displayName: "Additional Result Information",
            type: 'selector',
            values: values,
            comparators: comparator
          }
        }
        
        if (filterData.additionalTestInformationSet.size > 0) {
          const comparator = ["==", "!="]
          const values = Array.from(filterData.additionalTestInformationSet)

          this.additionalTestInformationFilter = {
            key: {
              type: 'additionalTestInformation',
            },
            displayName: "Additional Test Information",
            type: 'selector',
            values: values,
            comparators: comparator
          }
        }

        document.getElementById("table").innerHTML = res.data.html
        this.filterChanged()
        this.showOverlay = false

      }).catch((e) => {
        console.error(e)
      })
    },

    // triggered when clicked the first column (i.e. an UUID)
    rowHeadClicked(ev) {
      const target = ev.detail
      const rowIndex = target.getAttribute("data-rowindex")

      const rowData = this.tableData[rowIndex]
      if (rowData.isHead) return

      this.selectedRow = rowData
      this.detailsMode = 0
      this.showDetails = true
    },

    // triggered when clicked on an icon (a table cell)
    cellClicked(ev) {
      const target = ev.detail
      const identifier = target.getAttribute("data-identifier")
      const rowIndex = target.getAttribute("data-rowindex")

      const data = JSON.parse(JSON.stringify(this.tableData[rowIndex][identifier].data))
      if (!data) {
        return
      }

      this.detailsMode = 1
      if (data.DerivationContainer) {
        this.detailsMode = 2
        this.showPcap(this.tableData[rowIndex][identifier].data, null)
      }
      data.Identifier = identifier
      this.selectedCell = data
      this.showDetails = true
    },

    // triggered when clicked on column head
    colHeadClicked(ev) {
      const target = ev.detail
      const identifier = target.getAttribute("data-identifier")

      this.selectedCell = this.resultData[identifier]
      this.detailsMode = 1
      this.showDetails = true
    },

    updateParameters(route) {
      this.error = null
      if (route.query.selected) {
        this.selectedIdentifiers = route.query.selected.split(',')
        this.$store.commit("setSelectedIdentifiers", this.selectedIdentifiers)
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
    },

    async filterChanged() {
      console.log("Filter changed")
      this.showOverlay = true

      await this.processLargeArrayAsync(this.tableData, (val, i) => {
        if (i == 0) console.log("start loop")
        if (i == this.tableData.length - 1) console.log("end loop")
        const show = filter(this.filter, this.tableData[i])
        if (show) {
          document.querySelector(`tr[data-rowIndex='${i}']`).classList.remove("hidden")
        } else {
          document.querySelector(`tr[data-rowIndex='${i}']`).classList.add("hidden")
        }
      })

      console.log("finished")
      this.showOverlay = false
    },

    async submitEdit() {
      const data = {
        ...this.editPanelData,
        MethodName: this.testMethod.MethodName,
        ClassName: this.testMethod.ClassName
      }
      this.$http.post(`/testResult/edit`, data).then(() => {
        this.getStates()
      }).catch((e) => {
        console.error(e)
      })
    },

    async processLargeArrayAsync(array, fn, maxTimePerChunk, context) {
      context = context || this;
      maxTimePerChunk = maxTimePerChunk || 200;
      let index = 0;

      function now() {
        return new Date().getTime();
      }

      async function doChunk() {
        await new Promise((res) => {
          setTimeout(() => {
            res()
          }, 1)
        })

        return new Promise(function(res) {
          const startTime = now();
          while (index < array.length && (now() - startTime) <= maxTimePerChunk) {
            // callback called with args (value, index, array)
            fn.call(context, array[index], index, array);
            ++index;
          }
          if (index >= array.length) {
            res()
          } else {
            res(doChunk())
          }
        })
      }

      await doChunk();    
    }

  },
  created() {
    console.log("created")
    this.testResults = []

    document.addEventListener("cellClicked", this.cellClicked)
    document.addEventListener("rowHeadClicked", this.rowHeadClicked)
    document.addEventListener("colHeadClicked", this.colHeadClicked)
  },
  beforeRouteUpdate(to, from, next) {
    if (this.guardNavigation > 0) {
      this.guardNavigation -= 1
      next()
      return
    }

    console.log("beforeRouteUpdate")
    this.updateParameters(to)
    next()
  },
  activated() {
    this.updateParameters(this.$route)
  },
  components: {
    VueJsonPretty,
    TableFilter,
    EditPanel
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

.empty {
  background-color: #343a40 !important;
  border: 1px solid #464646 !important;
}

.stickyColumn {
  color: #fff !important;
  background-color: #343a40 !important;
  border: 1px solid #464646 !important;
  position: sticky;
  top: 0;
  z-index: 2;
}

.table-responsive {
  max-height: 99vh;
  overflow-y: auto;
}

.notSelectable {
  cursor: default !important;
}

.hidden {
  display: none
}

tr.rowIsNoHead span.cell,
tr.rowIsNoHead span.rowHead,
.pointer,
thead span.colHead {
  cursor: pointer
}

.centered {
  text-align: center;
}

thead th {
  vertical-align: middle !important;
}

tbody tr.rowIsHead th {
  font-family: inherit;
}

tbody tr th,
.monospace {
  font-family: monospace;
}


.table thead th {
  border-bottom: none !important;
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
