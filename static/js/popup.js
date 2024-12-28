// leanModal v1.1 by Ray Stone - http://finelysliced.com.au
// Dual licensed under the MIT and GPL


document.addEventListener('DOMContentLoaded', function() {
    if (!localStorage.getItem('cookieConsent')) {
        document.getElementById('cookieConsent').style.display = 'block';
    }

    document.getElementById('closeCookieConsent').addEventListener('click', function() {
        document.getElementById('cookieConsent').style.display = 'none';
    });

    document.querySelector('.cookieConsentOK').addEventListener('click', function() {
        localStorage.setItem('cookieConsent', '1');
        document.getElementById('cookieConsent').style.display = 'none';
    });
});
