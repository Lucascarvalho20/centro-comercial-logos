// ===========================
// INICIALIZAÇÃO
// ===========================
document.addEventListener('DOMContentLoaded', function () {
    initMenuMobile();
    initPopupAgendar();
    carregarDetalhesSala();
});

// ===========================
// MENU HAMBÚRGUER
// ===========================
function initMenuMobile() {
    var menuToggle = document.getElementById('menu-toggle');
    var navMenu    = document.getElementById('nav-menu');
    if (!menuToggle || !navMenu) return;

    var overlay = document.getElementById('nav-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'nav-overlay';
        overlay.className = 'nav-overlay';
        document.body.appendChild(overlay);
    }

    var aberto = false;

    function forcarCoresMenu() {
        if (window.innerWidth > 768) return;
        navMenu.querySelectorAll('.nav-list a').forEach(function (a) {
            if (!a.classList.contains('nav-ativo')) {
                a.style.setProperty('color', '#2C3E50', 'important');
            }
            a.style.setProperty('text-shadow', 'none', 'important');
        });
        menuToggle.style.setProperty('background', 'transparent', 'important');
        menuToggle.style.setProperty('background-color', 'transparent', 'important');
        menuToggle.style.setProperty('box-shadow', 'none', 'important');
        menuToggle.style.setProperty('border', 'none', 'important');
        menuToggle.querySelectorAll('.bar').forEach(function (b) {
            b.style.setProperty('background-color', '#fff', 'important');
        });
    }

    function abrirMenu() {
        aberto = true;
        navMenu.classList.add('active');
        menuToggle.classList.add('active');
        overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
        forcarCoresMenu();
    }
    function fecharMenu() {
        aberto = false;
        navMenu.classList.remove('active');
        menuToggle.classList.remove('active');
        overlay.classList.remove('active');
        document.body.style.overflow = '';
    }

    var _lastTouchToggle = 0;
    menuToggle.addEventListener('touchend', function (e) {
        e.preventDefault();
        var now = Date.now();
        if (now - _lastTouchToggle < 400) return;
        _lastTouchToggle = now;
        aberto ? fecharMenu() : abrirMenu();
    }, { passive: false });
    menuToggle.addEventListener('click', function () {
        aberto ? fecharMenu() : abrirMenu();
    });

    overlay.addEventListener('touchend', function (e) { e.preventDefault(); fecharMenu(); }, { passive: false });
    overlay.addEventListener('click', fecharMenu);

    navMenu.querySelectorAll('a').forEach(function (l) {
        var lastLT = 0;
        l.addEventListener('touchend', function (e) {
            var n = Date.now();
            if (n - lastLT < 400) return;
            lastLT = n;
            e.preventDefault();
            var href = l.getAttribute('href');
            fecharMenu();
            if (href && href !== '#') {
                setTimeout(function () { window.location.href = href; }, 10);
            }
        }, { passive: false });
        l.addEventListener('click', function () { fecharMenu(); });
    });
    var mobileBtn = navMenu.querySelector('.btn-contato');
    if (mobileBtn) mobileBtn.addEventListener('click', function () { fecharMenu(); });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && aberto) fecharMenu();
    });
}

// ===========================
// POPUPS
// ===========================
function abrirPopupContato() {
    var p = document.getElementById('popup-contato');
    if (p) { p.classList.add('active'); document.body.style.overflow = 'hidden'; }
}
function fecharPopupContato() {
    var p = document.getElementById('popup-contato');
    if (p) { p.classList.remove('active'); document.body.style.overflow = ''; }
}
function abrirPopupAgendar() {
    var p = document.getElementById('popup-agendar');
    if (p) { p.classList.add('active'); document.body.style.overflow = 'hidden'; }
}
function fecharPopupAgendar() {
    var p = document.getElementById('popup-agendar');
    if (p) { p.classList.remove('active'); document.body.style.overflow = ''; }
}
function initPopupAgendar() {
    var btn = document.getElementById('btnAgendarVisita');
    var fch = document.getElementById('fecharPopup');
    if (btn) btn.addEventListener('click', abrirPopupAgendar);
    if (fch) fch.addEventListener('click', fecharPopupAgendar);
}
window.addEventListener('click', function (e) {
    var pc = document.getElementById('popup-contato');
    if (pc && e.target === pc) fecharPopupContato();
    var pa = document.getElementById('popup-agendar');
    if (pa && e.target === pa) fecharPopupAgendar();
});

// ===========================
// LIGHTBOX
// ===========================
function abrirLightbox(src) {
    var lb  = document.getElementById('lightbox');
    var img = document.getElementById('lightbox-img');
    if (!lb || !img) return;
    img.src = src;
    lb.classList.add('active');
    document.body.style.overflow = 'hidden';
}
function fecharLightbox(e) {
    if (e && e.target && e.target.id === 'lightbox-img') return;
    var lb = document.getElementById('lightbox');
    if (!lb) return;
    lb.classList.remove('active');
    document.body.style.overflow = '';
}
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') fecharLightbox();
});

// ===========================
// WHATSAPP
// ===========================
function abrirWhats() {
    var params = new URLSearchParams(window.location.search);
    var id   = params.get('id');
    var nome = document.getElementById('salaTitle') ? document.getElementById('salaTitle').textContent : 'uma sala';
    var msg  = encodeURIComponent('Olá! Tenho interesse em ' + nome + '. Poderia me dar mais informações?');
    window.open('https://wa.me/5561999739224?text=' + msg, '_blank');
}

// ===========================
// CARREGAR DETALHES
// ===========================
function carregarDetalhesSala() {
    var params = new URLSearchParams(window.location.search);
    var salaId = parseInt(params.get('id'));
    if (!salaId) { window.location.href = 'salas.html'; return; }

    fetch('salas.json?v=' + Date.now())
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var sala = null;
            for (var i = 0; i < data.salas.length; i++) {
                if (data.salas[i].id === salaId) { sala = data.salas[i]; break; }
            }
            if (!sala) { window.location.href = 'salas.html'; return; }
            renderizarDetalhes(sala);
        })
        .catch(function (e) { console.error('Erro detalhes:', e); });
}

function renderizarDetalhes(sala) {
    document.title = sala.nome + ' - Prédio Logos';

    function setText(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; }
    setText('salaTitle',    sala.nome);
    setText('salaAndar',    sala.andar);
    setText('salaDescricao', sala.descricao);
    setText('salaTamanho',  sala.tamanho + ' m²');
    setText('salaSobre',    sala.sobre || 'Excelente espaço para o seu negócio.');

    var imgP = document.getElementById('imagemPrincipal');
    if (imgP) {
        imgP.src = sala.imagem_principal;
        imgP.onerror = function () { this.src = 'fotos_predio/foto_predio_1.jpg'; };
        imgP.onclick = function () { abrirLightbox(this.src); };
    }

    // Miniaturas
    var miniC = document.querySelector('.sala-detalhes-miniaturas');
    if (miniC && sala.fotos && sala.fotos.length > 0) {
        var mHtml = '';
        for (var i = 0; i < sala.fotos.length; i++) {
            var cls = 'sala-detalhes-miniatura' + (i === 0 ? ' active' : '');
            mHtml += '<img class="' + cls + '" src="' + sala.fotos[i]
                + '" alt="Vista ' + (i + 1) + '" onclick="mudarImagemDetalhes(this)"'
                + ' ondblclick="abrirLightbox(this.src)"'
                + ' title="Clique para selecionar • Duplo clique para ampliar"'
                + ' onerror="this.style.display=\'none\'">';
        }
        miniC.innerHTML = mHtml;
    }

    // Specs
    var specsC = document.querySelector('.sala-detalhes-specs');
    if (specsC && sala.specs && sala.specs.length > 0) {
        specsC.innerHTML = sala.specs.map(function (s) {
            return '<div class="spec-item"><span class="spec-icon">' + (s.icon || '📋') + '</span>'
                + '<div class="spec-info"><h4>' + s.titulo + '</h4><p>' + s.valor + '</p></div></div>';
        }).join('');
    }

    // Características
    var carL = document.querySelector('.caracteristicas-lista');
    if (carL) {
        carL.innerHTML = (sala.caracteristicas && sala.caracteristicas.length)
            ? sala.caracteristicas.map(function (c) { return '<li>✓ ' + c + '</li>'; }).join('')
            : '<li>✓ Sala em excelente estado de conservação</li>';
    }

    // Facilidades
    var facL = document.querySelector('.facilidades-lista');
    if (facL) {
        facL.innerHTML = (sala.facilidades && sala.facilidades.length)
            ? sala.facilidades.map(function (f) { return '<li>' + (f.icon || '🏢') + ' ' + f.valor + '</li>'; }).join('')
            : '<li>🅿️ Estacionamento</li><li>🛗 Elevador</li><li>🏢 Portaria</li>';
    }

    // Vídeo YouTube da sala (opcional)
    var videoSection = document.getElementById('sala-video-section');
    var videoContainer = document.getElementById('sala-video-container');
    if (videoSection && videoContainer && sala.youtube_url) {
        var vid = (sala.youtube_url.match(
            /(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/
        ) || [])[1];
        if (vid) {
            videoContainer.innerHTML = '<iframe'
                + ' src="https://www.youtube-nocookie.com/embed/' + vid + '?rel=0&modestbranding=1&playsinline=1"'
                + ' frameborder="0" allowfullscreen'
                + ' allow="autoplay; encrypted-media; fullscreen"'
                + ' title="Vídeo da sala"></iframe>';
            videoSection.style.display = 'block';
        }
    }
}

function mudarImagemDetalhes(el) {
    var img = document.getElementById('imagemPrincipal');
    if (img) img.src = el.src;
    var minis = document.querySelectorAll('.sala-detalhes-miniatura');
    for (var i = 0; i < minis.length; i++) minis[i].classList.remove('active');
    el.classList.add('active');
}
