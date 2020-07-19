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
    // route level code-splitting
    // this generates a separate chunk (about.[hash].js) for this route
    // which is lazy-loaded when the route is visited.
    component: () => import(/* webpackChunkName: "about" */ '../views/Analyzer.vue')
  }
]

const router = new VueRouter({
  routes
})

export default router
