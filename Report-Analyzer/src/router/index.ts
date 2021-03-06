import Vue from 'vue'
import VueRouter, { RouteConfig } from 'vue-router'
import Analyzer from '../views/Analyzer.vue'

Vue.use(VueRouter)

const routes: Array<RouteConfig> = [
  {
    path: '/',
    name: 'Analyzer',
    component: Analyzer,
    meta: {
      title: "TLS-Anvil Report Analyter"
    }
  },
  {
    path: '/analyzer',
    name: 'Analyzer',
    component: Analyzer,
    meta: {
      title: "TLS-Anvil Report Analyter"
    }
  },
  {
    path: '/states',
    name: 'states',
    component: () => import(/* webpackChunkName: "states" */ '../views/StateView.vue'),
    meta: {
      title: "TLS-Anvil Report Analyter"
    }
  },
  {
    path: '/manage',
    name: 'manage',
    component: () => import(/* webpackChunkName: "manage" */ '../views/Manage.vue'),
    meta: {
      title: "TLS-Anvil Report Analyter"
    }
  }
]

const router = new VueRouter({
  routes
})

export default router
