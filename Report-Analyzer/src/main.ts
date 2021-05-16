import Vue from 'vue'
import App from './App.vue'
import router from './router'
import store from './store'
import { BootstrapVue, IconsPlugin } from 'bootstrap-vue'
import axios from 'axios'
import VueAxios from 'vue-axios'

Vue.config.productionTip = false

// Install BootstrapVue
Vue.use(BootstrapVue)
// Optionally install the BootstrapVue icon components plugin
Vue.use(IconsPlugin)
Vue.use(VueAxios, axios)


console.log("mode", process.env)
if (process.env.NODE_ENV == 'production') {
  axios.defaults.baseURL = process.env.VUE_APP_REST_API_BASE_URL;
} else {
  axios.defaults.baseURL = 'http://localhost:5000/api/v1';
}

axios.defaults.headers.post['Content-Type'] = 'application/json';

const v = new Vue({
  router,
  store,
  render: h => h(App)
}).$mount('#app')
export default v


store.dispatch("getIdentifiers")


