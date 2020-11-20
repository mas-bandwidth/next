import { shallowMount, createLocalVue } from '@vue/test-utils'
import DownloadsWorkspace from '@/workspaces/DownloadsWorkspace.vue'
import {
  faDownload
} from '@fortawesome/free-solid-svg-icons'
import { library } from '@fortawesome/fontawesome-svg-core'
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'

describe('DownloadsWorkspace.vue', () => {
  const localVue = createLocalVue()

  const ICONS = [
    faDownload
  ]

  library.add(...ICONS)

  localVue.component('font-awesome-icon', FontAwesomeIcon)

  it('mounts the downloads workspace successfully', () => {
    const wrapper = shallowMount(DownloadsWorkspace, { localVue })
    expect(wrapper.exists()).toBe(true)
    wrapper.destroy()
  })

  it('checks if the links are correct', () => {
    const wrapper = shallowMount(DownloadsWorkspace, { localVue })
    expect(wrapper.find('.card-title').text()).toBe('Network Next SDK')

    expect(wrapper.findAll('.btn').length).toBe(2)
    expect(wrapper.findAll('.btn').at(0).text()).toBe('SDK v4.0.3')
    expect(wrapper.findAll('.btn').at(0).attributes('onclick'))
      .toBe("window.open('https://storage.googleapis.com/portal_sdk_download_storage/next-4.0.3.zip')")
    expect(wrapper.findAll('.btn').at(1).text()).toBe('Documentation')
    expect(wrapper.findAll('.btn').at(1).attributes('onclick'))
      .toBe("window.open('https://network-next-sdk.readthedocs-hosted.com/en/latest/')")
    wrapper.destroy()
  })
})
