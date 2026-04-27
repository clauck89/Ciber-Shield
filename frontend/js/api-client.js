/**
 * Cliente JavaScript para CyberShield AI Backend API
 * Integración con Have I Been Pwned API
 */

class CyberShieldAPI {
    constructor(baseURL = 'http://localhost:8000/api/v1') {
        this.baseURL = baseURL;
        this.timeout = 30000; // 30 segundos timeout
    }

    /**
     * Realiza una petición HTTP a la API
     * @param {string} endpoint - Endpoint de la API
     * @param {Object} options - Opciones de la petición
     * @returns {Promise} Response de la API
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        const config = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...options.headers
            },
            signal: controller.signal
        };

        try {
            const response = await fetch(url, config);
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({
                    error: 'HTTP_ERROR',
                    message: `HTTP ${response.status}: ${response.statusText}`
                }));
                throw new Error(errorData.message || 'Error en la petición');
            }

            return await response.json();
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('Tiempo de espera agotado');
            }
            throw error;
        } finally {
            clearTimeout(timeoutId);
        }
    }

    /**
     * Verifica el estado de salud de la API
     * @returns {Promise} Estado del servicio
     */
    async healthCheck() {
        return this.request('/health');
    }

    /**
     * Busca brechas asociadas a un email
     * @param {string} email - Email a consultar
     * @param {Object} options - Opciones de búsqueda
     * @returns {Promise} Lista de brechas y score de riesgo
     */
    async checkBreachedAccount(email, options = {}) {
        const params = new URLSearchParams({
            include_sensitive: options.includeSensitive || false,
            include_unverified: options.includeUnverified !== false,
            truncate: options.truncate !== false
        });

        return this.request(`/breaches/email/${encodeURIComponent(email)}?${params}`);
    }

    /**
     * Obtiene todas las brechas del sistema
     * @returns {Promise} Lista completa de brechas
     */
    async getAllBreaches() {
        return this.request('/breaches/all');
    }

    /**
     * Obtiene detalles de una brecha específica
     * @param {string} breachName - Nombre de la brecha
     * @returns {Promise} Detalles de la brecha
     */
    async getBreachDetails(breachName) {
        return this.request(`/breach/${encodeURIComponent(breachName)}`);
    }

    /**
     * Verifica si una contraseña está comprometida
     * @param {string} password - Contraseña a verificar
     * @param {boolean} includePadding - Incluir padding para privacidad
     * @returns {Promise} Información sobre la contraseña
     */
    async checkPwnedPassword(password, includePadding = true) {
        return this.request('/password/check', {
            method: 'POST',
            body: JSON.stringify({
                password: password,
                include_padding: includePadding
            })
        });
    }

    /**
     * Busca pastes asociados a un email
     * @param {string} email - Email a consultar
     * @returns {Promise} Lista de pastes encontrados
     */
    async getPastesForEmail(email) {
        return this.request(`/pastes/email/${encodeURIComponent(email)}`);
    }

    /**
     * Obtiene todos los tipos de datos comprometidos
     * @returns {Promise} Lista de tipos de datos
     */
    async getDataClasses() {
        return this.request('/dataclasses');
    }
}

/**
 * Utilidades para la interfaz de usuario
 */
class CyberShieldUI {
    constructor(apiClient) {
        this.api = apiClient;
        this.loadingStates = new Map();
    }

    /**
     * Muestra/oculta estado de carga
     * @param {string} elementId - ID del elemento
     * @param {boolean} loading - Estado de carga
     */
    setLoading(elementId, loading) {
        const element = document.getElementById(elementId);
        if (!element) return;

        if (loading) {
            this.loadingStates.set(elementId, element.innerHTML);
            element.innerHTML = `
                <div class="flex items-center justify-center">
                    <div class="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                    <span class="ml-2">Procesando...</span>
                </div>
            `;
            element.disabled = true;
        } else {
            element.innerHTML = this.loadingStates.get(elementId) || '';
            element.disabled = false;
            this.loadingStates.delete(elementId);
        }
    }

    /**
     * Muestra una notificación al usuario
     * @param {string} message - Mensaje a mostrar
     * @param {string} type - Tipo: success, error, warning, info
     */
    showNotification(message, type = 'info') {
        // Crear elemento de notificación
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 max-w-sm ${
            type === 'success' ? 'bg-green-500 text-white' :
            type === 'error' ? 'bg-red-500 text-white' :
            type === 'warning' ? 'bg-yellow-500 text-white' :
            'bg-blue-500 text-white'
        }`;
        notification.innerHTML = `
            <div class="flex items-center">
                <span class="flex-1">${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-white hover:text-gray-200">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                    </svg>
                </button>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto-eliminar después de 5 segundos
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    /**
     * Formatea el score de riesgo con colores
     * @param {number} score - Score de riesgo (0-100)
     * @returns {Object} Objeto con clase y texto
     */
    formatRiskScore(score) {
        if (score === 0) {
            return { class: 'bg-green-500', text: 'Seguro', level: 'bajo' };
        } else if (score <= 25) {
            return { class: 'bg-yellow-500', text: 'Riesgo Bajo', level: 'bajo' };
        } else if (score <= 50) {
            return { class: 'bg-orange-500', text: 'Riesgo Medio', level: 'medio' };
        } else if (score <= 75) {
            return { class: 'bg-red-500', text: 'Riesgo Alto', level: 'alto' };
        } else {
            return { class: 'bg-red-700', text: 'Riesgo Crítico', level: 'crítico' };
        }
    }

    /**
     * Formatea fecha para mostrar
     * @param {string} dateString - Fecha en formato ISO
     * @returns {string} Fecha formateada
     */
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('es-ES', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    }

    /**
     * Valida formato de email
     * @param {string} email - Email a validar
     * @returns {boolean} Si es válido
     */
    validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }

    /**
     * Enmascara email para mostrarlo parcialmente
     * @param {string} email - Email a enmascarar
     * @returns {string} Email enmascarado
     */
    maskEmail(email) {
        if (!this.validateEmail(email)) return email;
        
        const [local, domain] = email.split('@');
        if (local.length <= 2) {
            return '*'.repeat(local.length) + '@' + domain;
        }
        
        return local[0] + '*'.repeat(local.length - 2) + local[local.length - 1] + '@' + domain;
    }

    /**
     * Genera HTML para mostrar brechas
     * @param {Array} breaches - Lista de brechas
     * @returns {string} HTML generado
     */
    generateBreachesHTML(breaches) {
        if (!breaches || breaches.length === 0) {
            return `
                <div class="bg-green-50 border border-green-200 rounded-lg p-6">
                    <div class="flex items-center">
                        <svg class="w-8 h-8 text-green-500 mr-3" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                        </svg>
                        <div>
                            <h3 class="text-lg font-semibold text-green-800">¡Buenas noticias!</h3>
                            <p class="text-green-600">No encontramos brechas asociadas a este email.</p>
                        </div>
                    </div>
                </div>
            `;
        }

        return breaches.map(breach => `
            <div class="bg-white border border-gray-200 rounded-lg p-4 mb-4 shadow-sm">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <h3 class="text-lg font-semibold text-gray-900">${breach.title}</h3>
                        <p class="text-sm text-gray-600 mb-2">${breach.domain}</p>
                        <p class="text-gray-700 text-sm mb-3">${breach.description}</p>
                        
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                            <div>
                                <span class="font-medium text-gray-500">Fecha:</span>
                                <span class="ml-2 text-gray-700">${this.formatDate(breach.breach_date)}</span>
                            </div>
                            <div>
                                <span class="font-medium text-gray-500">Cuentas afectadas:</span>
                                <span class="ml-2 text-gray-700">${breach.pwn_count.toLocaleString('es-ES')}</span>
                            </div>
                            <div>
                                <span class="font-medium text-gray-500">Verificada:</span>
                                <span class="ml-2">
                                    ${breach.is_verified ? 
                                        '<span class="text-green-600">✓ Sí</span>' : 
                                        '<span class="text-yellow-600">⚠ No verificada</span>'
                                    }
                                </span>
                            </div>
                        </div>
                        
                        <div class="mt-3">
                            <span class="font-medium text-gray-500 text-sm">Datos comprometidos:</span>
                            <div class="mt-1 flex flex-wrap gap-1">
                                ${breach.data_classes.map(dataClass => 
                                    `<span class="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded">${dataClass}</span>`
                                ).join('')}
                            </div>
                        </div>
                    </div>
                    
                    ${breach.logo_path ? 
                        `<img src="https://haveibeenpwned.com/Content/Images/PwnedLogos/${breach.logo_path}" 
                              alt="${breach.name}" class="w-16 h-16 ml-4 rounded">` : 
                        ''
                    }
                </div>
            </div>
        `).join('');
    }
}

// Instancias globales
window.CyberShieldAPI = CyberShieldAPI;
window.CyberShieldUI = CyberShieldUI;

// Crear instancias por defecto
window.api = new CyberShieldAPI();
window.ui = new CyberShieldUI(window.api);
