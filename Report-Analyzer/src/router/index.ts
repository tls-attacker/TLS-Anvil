import Vue from 'vue'
import VueRouter, { RouteConfig } from 'vue-router'
import Upload from '../views/Main_Upload.vue'

Vue.use(VueRouter)

const routes: Array<RouteConfig> = [
  {
    path: '/',
    name: 'Upload',
    component: Upload
  },
  {
    path: '/analyzer',
    name: 'Analyzer',
    component: () => import(/* webpackChunkName: "analyzer" */ '../views/Analyzer.vue')
  },
  {
    path: '/states',
    name: 'states',
    component: () => import(/* webpackChunkName: "states" */ '../views/StateView.vue')
  },
  {
    path: '/manage',
    name: 'manage',
    component: () => import(/* webpackChunkName: "manage" */ '../views/Manage.vue')
  }
]

const router = new VueRouter({
  routes
})

export default router
