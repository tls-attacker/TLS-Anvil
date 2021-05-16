import Vue from 'vue'
import Vuex from 'vuex'
import vueI from '../main'

Vue.use(Vuex)

export default new Vuex.Store({
  state: {
    allIdentifiers: [],
    selectedIdentifiers: []
  },
  mutations: {
    setAllIdentifiers(state, identifiers) {
      state.allIdentifiers = identifiers
    },
    setSelectedIdentifiers(state, identifiers) {
      state.selectedIdentifiers = identifiers
    }
  },
  actions: {
    getIdentifiers(context) {
      vueI.$http.get("/testReportIdentifiers").then((r) => {
        context.commit("setAllIdentifiers", r.data)
      }).catch((e) => {
        console.error("Getting Identifiers failed!", e)
      })
    }
  },
  modules: {
  }
})
