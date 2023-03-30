<template>
    <div class="subscription-form page">
        <h2 class="content__title">Subscribe</h2>
        <form @submit.prevent="submitForm" class="theme-default-content">
            <div class="form-group">
                <label for="firstName" class="label">First Name:</label>
                <input type="text" id="firstName" v-model="firstName" required class="input" />
            </div>
            <div class="form-group">
                <label for="lastName" class="label">Last Name:</label>
                <input type="text" id="lastName" v-model="lastName" required class="input" />
            </div>
            <div class="form-group">
                <label for="email" class="label">Email:</label>
                <input type="email" id="email" v-model="email" required class="input" />
            </div>
            <div class="form-group">
                <label for="company" class="label">Company (Optional):</label>
                <input type="text" id="company" v-model="company" class="input" />
            </div>
            <div class="form-group">
                <label for="position" class="label">Position (Optional):</label>
                <input type="text" id="position" v-model="position" class="input" />
            </div>
            <div class="form-group">
                <input type="checkbox" id="acceptTerms" v-model="acceptTerms" required />
                <label for="acceptTerms">
                    I accept the
                    <a href="/terms" target="_blank">Terms</a> and
                    <a href="/privacy" target="_blank">Privacy Policy</a>.
                </label>
            </div>
            <div>
                <button type="submit" class="submit-button">Subscribe</button>
            </div>
            <div v-if="errorMessage" class="error-message">
                {{ errorMessage }}
            </div>
        </form>
    </div>
</template>
    
  
<script>
import axios from 'axios'

export default {
    data() {
        return {
            firstName: '',
            lastName: '',
            email: '',
            company: '',
            position: '',
            errorMessage: '',
            acceptTerms: false,
        }
    },
    methods: {
        async submitForm() {
            try {
                await axios.post('YOUR_API_GATEWAY_URL', {
                    firstName: this.firstName,
                    lastName: this.lastName,
                    email: this.email,
                    company: this.company,
                    position: this.position,
                })

                // Clear the form fields and error message
                this.firstName = ''
                this.lastName = ''
                this.email = ''
                this.company = ''
                this.position = ''
                this.errorMessage = ''

                // Redirect the user to the payment page
                this.$router.push('/payment')
            } catch (error) {
                this.errorMessage = error.response.data.message || 'An error occurred. Please try again.'
            }
        },
    },
}
</script>
  
<style scoped>
.form-group {
    margin-bottom: 1.5rem;
}

.label {
    display: block;
    margin-bottom: 0.5rem;
}

.input {
    display: block;
    width: 100%;
    padding: 0.5rem 0;
    font-size: 1rem;
    line-height: 1.5;
    background-clip: padding-box;
    border: 1px solid #ced4da;
    border-radius: 0.25rem;
    transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}

.submit-button {
    background-color: #3EAF7C;
    padding: 12px 24px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;
    margin: 4px 2px;
    cursor: pointer;
    transition: opacity 0.3s;
    border: 2px solid #3aa675;
    border-radius: 4px;
    width: 100%;
}

.submit-button:hover {
    opacity: 0.8;
}


.error-message {
    margin-top: 1rem;
    color: #dc3541
}
</style>
  