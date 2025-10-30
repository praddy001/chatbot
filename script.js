class ThemeManager {
    constructor() {
        this.currentTheme = localStorage.getItem('theme') || 'light';
        this.init();
    }

    init() {
        this.applyTheme(this.currentTheme);
        if (elements.themeToggle) {
            elements.themeToggle.addEventListener('click', () => this.toggleTheme());
        }
    }

    applyTheme(theme) {
        document.body.classList.toggle('dark-mode', theme === 'dark');
        if (elements.themeToggle) {
            elements.themeToggle.innerHTML = theme === 'dark' 
                ? '<i class="fas fa-sun"></i>' 
                : '<i class="fas fa-moon"></i>';
        }
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.applyTheme(this.currentTheme);
        localStorage.setItem('theme', this.currentTheme);
    }
}

// Export for potential external use
window.AyurConnect = {
    Utils,
    ThemeManager,
    NavigationManager,
    ModalManager,
    TabManager,
    FormManager,
    AnimationManager
};
