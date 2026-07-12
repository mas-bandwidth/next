import { createApp } from 'vue'
import App from './App.vue'
import "bootstrap/dist/css/bootstrap.min.css"
import "bootstrap"
import 'bootstrap-icons/font/bootstrap-icons.css';
import router from './router'
import 'uplot/dist/uPlot.min.css';
import axios from 'axios'

// every view relies on this default header for its portal API requests
axios.defaults.headers.common = {'Authorization': `Bearer ${import.meta.env.VITE_PORTAL_API_KEY}`}

createApp(App).use(router).mount('#app')
