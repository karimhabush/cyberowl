import { defineClientConfig } from 'vuepress/client'
import FloatingSkillButton from './components/FloatingSkillButton.vue'
import { h } from 'vue'

export default defineClientConfig({
    rootComponents: [FloatingSkillButton],
})
