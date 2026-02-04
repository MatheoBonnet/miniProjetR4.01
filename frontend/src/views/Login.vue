<template>
  <div class="container">
    <h1>🔐 Connexion</h1>

    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="success" class="success">{{ success }}</div>

    <form @submit.prevent="handleLogin">
      <div class="form-group">
        <label for="email">Email</label>
        <input
          type="email"
          id="email"
          v-model="form.email"
          placeholder="jean.dupont@example.com"
          required
        />
      </div>

      <div class="form-group">
        <label for="password">Mot de passe</label>
        <input
          type="password"
          id="password"
          v-model="form.password"
          placeholder="Votre mot de passe"
          required
        />
      </div>

      <button type="submit" :disabled="loading">
        {{ loading ? 'Connexion...' : 'Se connecter' }}
      </button>
    </form>

    <div class="link">
      Pas encore de compte ? <router-link to="/register">S'inscrire</router-link>
    </div>

    <div class="divider">
      <span>OU</span>
    </div>

    <button @click="signInWithGoogle" type="button" class="google-btn">
      <svg class="google-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
      Se connecter avec Google
    </button>

    <div class="jwt-info">
      <h3>💡 Démo JWT</h3>
      <p>
        ✅ Après connexion, un <strong>Access Token</strong> JWT est stocké<br>
        ✅ Ce token est envoyé dans le header <code>Authorization: Bearer ...</code><br>
        ✅ Le serveur vérifie le token sans consulter de session
      </p>
    </div>
  </div>
</template>

<script>
import { authService } from '../services/api'

export default {
  name: 'Login',
  data() {
    return {
      form: {
        email: '',
        password: ''
      },
      error: null,
      success: null,
      loading: false
    }
  },
  mounted() {
    // Afficher un message d'erreur si OAuth a échoué
    const error = this.$route.query.error
    if (error === 'google_auth_failed') {
      this.error = 'Échec de l\'authentification Google'
    } else if (error === 'token_generation_failed') {
      this.error = 'Erreur lors de la génération du token'
    }
  },
  methods: {
    async handleLogin() {
      this.error = null
      this.success = null
      this.loading = true

      try {
        const response = await authService.login(this.form)
        this.success = response.message

        // Rediriger vers home après connexion réussie
        setTimeout(() => {
          this.$router.push('/home')
        }, 1000)
      } catch (err) {
        this.error = err.response?.data?.message || 'Erreur lors de la connexion'
      } finally {
        this.loading = false
      }
    },
    signInWithGoogle() {
      // Redirection vers le backend qui initie OAuth
      window.location.href = `${import.meta.env.VITE_API_URL}/auth/google`
    }
  }
}
</script>

<style scoped>
.divider {
  display: flex;
  align-items: center;
  text-align: center;
  margin: 2rem 0;
  color: #666;
}

.divider::before,
.divider::after {
  content: '';
  flex: 1;
  border-bottom: 1px solid #ddd;
}

.divider span {
  padding: 0 1rem;
  font-size: 0.9rem;
  font-weight: 500;
}

.google-btn {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  padding: 0.75rem 1.5rem;
  background: white;
  color: #3c4043;
  border: 1px solid #dadce0;
  border-radius: 4px;
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.google-btn:hover {
  background: #f8f9fa;
  border-color: #d2d4d6;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
}

.google-icon {
  width: 20px;
  height: 20px;
}

.jwt-info {
  margin-top: 2rem;
  padding: 1.5rem;
  background: #f0f7ff;
  border-left: 4px solid #2563eb;
  border-radius: 4px;
}

.jwt-info h3 {
  margin: 0 0 0.75rem 0;
  color: #1e40af;
  font-size: 1.1rem;
}

.jwt-info p {
  margin: 0;
  color: #1e3a8a;
  line-height: 1.6;
  font-size: 0.95rem;
}
</style>
