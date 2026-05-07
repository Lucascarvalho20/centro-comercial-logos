// ===========================
// INICIALIZAÇÃO
// ===========================
document.addEventListener('DOMContentLoaded', function () {
    initMenuMobile();
    initPopupAgendar();
    carregarSalas();
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

    var _lastTouch = 0;
    menuToggle.addEventListener('touchend', function (e) {
        e.preventDefault();
        var now = Date.now();
        if (now - _lastTouch < 400) return;
        _lastTouch = now;
        aberto ? fecharMenu() : abrirMenu();
    }, { passive: false });
    menuToggle.addEventListener('click', function () { aberto ? fecharMenu() : abrirMenu(); });

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

    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && aberto) fecharMenu(); });
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
    if (e && e.target && e.target.id === 'lightbox-img') return; // clique na imagem não fecha
    var lb = document.getElementById('lightbox');
    if (!lb) return;
    lb.classList.remove('active');
    document.body.style.overflow = '';
}

document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') fecharLightbox();
});

// ===========================
// DADOS E ESTADO DOS FILTROS
// ===========================
var todasSalas    = [];
var filtroAndar   = 'todos';
var filtroTamanho = '';  // '' | 'maior-menor' | 'menor-maior'

// ===========================
// CARREGAR SALAS
// ===========================
function carregarSalas() {
    fetch('salas.json?v=' + Date.now())
        .then(function (r) { return r.json(); })
        .then(function (data) {
            // Salas inativas NÃO aparecem na página pública (só no admin)
            todasSalas = (data.salas || []).filter(function (s) { return !s.inativa; });
            aplicarFiltros();
            configurarFiltros();
        })
        .catch(function (err) {
            console.error('Erro ao carregar salas:', err);
            var g = document.getElementById('salas-grid');
            if (g) g.innerHTML = '<p style="padding:40px;text-align:center;color:#999">Erro ao carregar salas.</p>';
        });
}

// ===========================
// RENDERIZAR SALAS
// ===========================
function renderizarSalas(salas) {
    var grid = document.getElementById('salas-grid');
    var nao  = document.getElementById('nao-encontrado');
    if (!grid) return;

    if (!salas || salas.length === 0) {
        grid.innerHTML = '';
        if (nao) nao.style.display = 'block';
        return;
    }
    if (nao) nao.style.display = 'none';

    var html = '';
    for (var i = 0; i < salas.length; i++) {
        var sala = salas[i];

        // Andar normalizado para badge
        var a = (sala.andar || '').toLowerCase();
        try { a = (sala.andar || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, ''); } catch (e) {}
        var badge = (a.indexOf('terreo') >= 0 || a.indexOf('t\u00e9rreo') >= 0) ? 'terreo'
            : a.indexOf('subsolo') >= 0 ? 'subsolo'
            : a.indexOf('primeiro') >= 0 ? 'primeiro'
            : a.indexOf('segundo') >= 0 ? 'segundo' : 'destaque';

        // Overlay de status
        var overlayHtml = sala.alugada
            ? '<div class="sala-alugada-overlay"><span class="badge-alugada">ALUGADA</span></div>'
            : sala.inativa
            ? '<div class="sala-inativa-overlay"><span class="badge-inativa">INDISPON\u00CDVEL</span></div>'
            : '';

        // Badge destaque (estrela no canto superior direito)
        var destaqueBadge = sala.destaque
            ? '<span class="badge-destaque-card">\u2605 DESTAQUE</span>'
            : '';

        // Classe do card
        var cardClass = 'sala-card' + (sala.destaque ? ' em-destaque' : '');

        var onerr  = "this.src='fotos_predio/foto_predio_1.jpg'";
        var detUrl = 'detalhes.html?id=' + sala.id;

        html += '<div class="' + cardClass + '" style="animation-delay:' + (i * 0.06) + 's">';
        html += '<div class="sala-image">' + overlayHtml + destaqueBadge;
        html += '<img src="' + sala.imagem_principal + '" alt="' + sala.nome + '" onerror="' + onerr + '" onclick="abrirLightbox(this.src)">';
        html += '<span class="sala-badge ' + badge + '">' + sala.andar + '</span></div>';
        html += '<div class="sala-content">';
        html += '<h3 class="sala-titulo">' + sala.nome + '</h3>';
        html += '<p class="sala-descricao">' + sala.descricao + '</p>';
        html += '<div class="sala-features">';
        html += '<div class="sala-feature"><span class="sala-feature-icon">\uD83D\uDCCF</span>' + sala.tamanho + ' m\u00B2</div>';
        html += '<div class="sala-feature"><span class="sala-feature-icon">\uD83C\uDFE2</span>' + sala.andar + '</div>';
        html += '</div>';
        html += '<button class="sala-btn" onclick="window.location.href=\'' + detUrl + '\'">Mais Informa\u00E7\u00F5es \u2192</button>';
        html += '</div></div>';
    }
    grid.innerHTML = html;
}

// ===========================
// APLICAR FILTROS + ORDENAÇÃO DESTAQUE
// ===========================
function aplicarFiltros() {
    var res = todasSalas.slice();

    // 1. Filtro por andar
    if (filtroAndar !== 'todos') {
        res = res.filter(function (s) {
            var a = (s.andar || '').toLowerCase();
            try { a = a.normalize('NFD').replace(/[\u0300-\u036f]/g, ''); } catch (e) {}
            return a.indexOf(filtroAndar) >= 0;
        });
    }

    // 2. Ordenação por tamanho OU destaque
    if (filtroTamanho === 'maior-menor') {
        // Tamanho: ignora destaque, ordena só por tamanho
        res.sort(function (a, b) { return b.tamanho - a.tamanho; });
    } else if (filtroTamanho === 'menor-maior') {
        // Tamanho: ignora destaque, ordena só por tamanho
        res.sort(function (a, b) { return a.tamanho - b.tamanho; });
    } else {
        // Sem filtro de tamanho: destaque vem primeiro
        // Dentro de cada grupo (destaque / não-destaque), mantém a ordem original do JSON
        res.sort(function (a, b) {
            var da = a.destaque ? 1 : 0;
            var db = b.destaque ? 1 : 0;
            return db - da;  // destaque (1) antes de não-destaque (0)
        });
    }

    renderizarSalas(res);
}

// ===========================
// CONFIGURAR FILTROS
// ===========================
function configurarFiltros() {
    var btnAndar = document.getElementById('btn-andar');
    var dropdown = document.getElementById('lista-andar');
    var label    = document.getElementById('label-andar');
    var btnTodos = document.getElementById('filtro-todos');
    var selTam   = document.getElementById('filtro-tamanho');

    if (btnAndar && dropdown) {
        btnAndar.addEventListener('click', function (e) {
            e.stopPropagation();
            dropdown.classList.toggle('open');
        });
        document.addEventListener('click', function () { dropdown.classList.remove('open'); });
    }

    var items = document.querySelectorAll('.dropdown-item');
    for (var i = 0; i < items.length; i++) {
        (function (item) {
            item.addEventListener('click', function () {
                filtroAndar = this.getAttribute('data-value');
                if (label) label.textContent = this.getAttribute('data-label');
                if (btnTodos) btnTodos.classList.remove('filtro-ativo');
                if (btnAndar) btnAndar.classList.add('filtro-ativo');
                if (dropdown) dropdown.classList.remove('open');
                aplicarFiltros();
            });
        })(items[i]);
    }

    if (btnTodos) {
        btnTodos.addEventListener('click', function () {
            filtroAndar = 'todos';
            if (label) label.textContent = 'Andar';
            btnTodos.classList.add('filtro-ativo');
            if (btnAndar) btnAndar.classList.remove('filtro-ativo');
            aplicarFiltros();
        });
    }

    if (selTam) {
        selTam.addEventListener('change', function () {
            filtroTamanho = this.value;
            aplicarFiltros();
        });
    }
}
