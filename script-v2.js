// ══════════════════════════════════════════════
// INICIALIZAÇÃO
// ══════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', function () {
    initHeaderScroll();
    initMenuMobile();
    initFAQ();
    initPopupAgendar();
    initSmoothScroll();
    carregarHeroVideo();
    carregarGaleriaPredia();
    carregarPontos();
    carregarClientes();
});

// ══════════════════════════════════════════════
// HEADER — scroll effect
// ══════════════════════════════════════════════
function initHeaderScroll() {
    var h = document.getElementById('header');
    if (!h) return;
    function aplicarEstiloMobile() {
        if (window.innerWidth <= 768) {
            h.style.setProperty('background', '#1A1F3A', 'important');
            h.style.setProperty('background-color', '#1A1F3A', 'important');
            h.querySelectorAll('.menu-toggle .bar').forEach(function (b) {
                b.style.setProperty('background-color', '#fff', 'important');
            });
            var logoT = h.querySelectorAll('.logo-text, .logo-icon, .admin-icon');
            logoT.forEach(function (el) { el.style.setProperty('color', '#fff', 'important'); });
        } else {
            h.style.background = '';
            h.style.backgroundColor = '';
        }
    }
    function upd() {
        h.classList.toggle('header-scrolled', window.scrollY > 60);
        aplicarEstiloMobile();
    }
    upd();
    window.addEventListener('scroll', upd, { passive: true });
    window.addEventListener('resize', aplicarEstiloMobile, { passive: true });
}

// ══════════════════════════════════════════════
// MENU HAMBÚRGUER
// ══════════════════════════════════════════════
function initMenuMobile() {
    var toggle  = document.getElementById('menu-toggle');
    var navMenu = document.getElementById('nav-menu');
    if (!toggle || !navMenu) return;

    var overlay = document.getElementById('nav-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'nav-overlay';
        overlay.className = 'nav-overlay';
        document.body.appendChild(overlay);
    }
    var open = false;

    function forcarCoresMenu() {
        if (window.innerWidth > 768) return;
        navMenu.querySelectorAll('.nav-list a').forEach(function (a) {
            if (!a.classList.contains('nav-ativo')) {
                a.style.setProperty('color', '#2C3E50', 'important');
            }
            a.style.setProperty('text-shadow', 'none', 'important');
        });
        toggle.style.setProperty('background', 'transparent', 'important');
        toggle.style.setProperty('background-color', 'transparent', 'important');
        toggle.style.setProperty('box-shadow', 'none', 'important');
        toggle.style.setProperty('border', 'none', 'important');
        toggle.querySelectorAll('.bar').forEach(function (b) {
            b.style.setProperty('background-color', '#fff', 'important');
        });
    }

    function abre() {
        open = true;
        navMenu.classList.add('active');
        toggle.classList.add('active');
        overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
        forcarCoresMenu();
    }
    function fecha() {
        open = false;
        navMenu.classList.remove('active');
        toggle.classList.remove('active');
        overlay.classList.remove('active');
        document.body.style.overflow = '';
    }

    var lastT = 0;
    toggle.addEventListener('touchend', function (e) {
        e.preventDefault();
        var n = Date.now();
        if (n - lastT < 400) return;
        lastT = n;
        open ? fecha() : abre();
    }, { passive: false });
    toggle.addEventListener('click', function () { open ? fecha() : abre(); });

    overlay.addEventListener('touchend', function (e) { e.preventDefault(); fecha(); }, { passive: false });
    overlay.addEventListener('click', fecha);

    navMenu.querySelectorAll('a').forEach(function (l) {
        var lastLT = 0;

        l.addEventListener('touchend', function (e) {
            var n = Date.now();
            if (n - lastLT < 400) return;
            lastLT = n;
            e.preventDefault(); // impede o click sintético subsequente
            var href = l.getAttribute('href');
            fecha();
            if (href && href.charAt(0) === '#' && href.length > 1) {
                var target = document.querySelector(href);
                if (target) {
                    // Aguarda o browser processar overflow: '' antes de rolar
                    setTimeout(function () { target.scrollIntoView({ behavior: 'smooth' }); }, 50);
                }
            } else if (href && href !== '#') {
                setTimeout(function () { window.location.href = href; }, 10);
            }
        }, { passive: false });

        l.addEventListener('click', function (e) {
            fecha();
            var href = l.getAttribute('href');
            if (href && href.charAt(0) === '#' && href.length > 1) {
                e.preventDefault();
                var target = document.querySelector(href);
                if (target) {
                    setTimeout(function () { target.scrollIntoView({ behavior: 'smooth' }); }, 50);
                }
            }
        });
    });

    var mBtn = navMenu.querySelector('.btn-contato');
    if (mBtn) mBtn.addEventListener('click', fecha);

    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && open) fecha(); });
}

// ══════════════════════════════════════════════
// FAQ
// ══════════════════════════════════════════════
function initFAQ() {
    var items = document.querySelectorAll('.faq-item');
    items.forEach(function (item) {
        var btn = item.querySelector('.faq-question');
        if (!btn) return;
        btn.addEventListener('click', function () {
            var was = item.classList.contains('ativo');
            items.forEach(function (i) { i.classList.remove('ativo'); });
            if (!was) item.classList.add('ativo');
        });
    });
}

// ══════════════════════════════════════════════
// POPUPS
// ══════════════════════════════════════════════
function abrirPopupContato() {
    var p = document.getElementById('popup-contato');
    if (p) { p.classList.add('active'); document.body.style.overflow = 'hidden'; }
}
function fecharPopupContato() {
    var p = document.getElementById('popup-contato');
    if (p) { p.classList.remove('active'); document.body.style.overflow = ''; }
}
function initPopupAgendar() {
    var b = document.getElementById('btnAgendarVisita');
    var f = document.getElementById('fecharPopup');
    if (b) b.addEventListener('click', abrirPopupAgendar);
    if (f) f.addEventListener('click', fecharPopupAgendar);
}
function abrirPopupAgendar() {
    var p = document.getElementById('popup-agendar');
    if (p) { p.classList.add('active'); document.body.style.overflow = 'hidden'; }
}
function fecharPopupAgendar() {
    var p = document.getElementById('popup-agendar');
    if (p) { p.classList.remove('active'); document.body.style.overflow = ''; }
}
window.addEventListener('click', function (e) {
    var pc = document.getElementById('popup-contato');
    if (pc && e.target === pc) fecharPopupContato();
    var pa = document.getElementById('popup-agendar');
    if (pa && e.target === pa) fecharPopupAgendar();
});

// ══════════════════════════════════════════════
// WHATSAPP
// ══════════════════════════════════════════════
function abrirWhatsApp() { window.open('https://wa.me/5561999739224', '_blank'); }

// ══════════════════════════════════════════════
// HERO — vídeo fullscreen sem corte e sem travar
// ══════════════════════════════════════════════
function carregarHeroVideo() {
    var wrap = document.getElementById('hero-video-wrap');
    if (!wrap) return;

    fetch('galeria_home.json?nc=' + Date.now())
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (d && d.youtube_url) {
                montarYoutubeHero(wrap, d.youtube_url);
                return;
            }
            var src = '';
            if (d && d.videos && d.videos.length) src = d.videos[0];
            else if (d && d.video) src = d.video;
            montarVideoHero(wrap, src || 'videos/video predio.mp4');
        })
        .catch(function () { montarVideoHero(wrap, 'videos/video predio.mp4'); });
}

function extrairYoutubeId(url) {
    var m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    return m ? m[1] : null;
}

function montarYoutubeHero(container, url) {
    var vid = extrairYoutubeId(url);
    if (!vid) { montarVideoHero(container, 'videos/video predio.mp4'); return; }
    container.innerHTML = '';
    var iframe = document.createElement('iframe');
    iframe.src = 'https://www.youtube-nocookie.com/embed/' + vid
        + '?autoplay=1&mute=1&loop=1&playlist=' + vid
        + '&controls=0&showinfo=0&rel=0&iv_load_policy=3&modestbranding=1&playsinline=1&enablejsapi=0';
    iframe.setAttribute('frameborder', '0');
    iframe.setAttribute('allow', 'autoplay; encrypted-media');
    iframe.setAttribute('allowfullscreen', '');
    iframe.setAttribute('loading', 'lazy');
    iframe.setAttribute('title', '');
    iframe.style.cssText = [
        'position:absolute',
        'top:50%',
        'left:50%',
        'width:177.78vh',
        'min-width:100%',
        'height:56.25vw',
        'min-height:100%',
        'transform:translate(-50%,-50%)',
        'pointer-events:none',
        'border:none'
    ].join(';');
    container.appendChild(iframe);
}

function montarVideoHero(container, src) {
    container.innerHTML = '';
    var v = document.createElement('video');
    v.setAttribute('autoplay', '');
    v.setAttribute('muted', '');   // sem áudio
    v.setAttribute('loop', '');
    v.setAttribute('playsinline', '');
    v.setAttribute('preload', 'auto');
    v.muted = true;                // garantia extra — alguns browsers ignoram o atributo
    v.volume = 0;                  // volume zero como fallback
    v.style.cssText = [
        'position:absolute','top:0','left:0',
        'width:100%','height:100%',
        'object-fit:cover','object-position:center center',
        'display:block','pointer-events:none'
    ].join(';');
    var s = document.createElement('source');
    s.src  = src;
    s.type = 'video/mp4';
    v.appendChild(s);
    container.appendChild(v);
    v.load();
    var p = v.play();
    if (p && p.catch) {
        p.catch(function () {
            document.addEventListener('touchstart', function tryPlay() {
                v.muted = true; v.play().catch(function () {});
                document.removeEventListener('touchstart', tryPlay);
            }, { once: true, passive: true });
            document.addEventListener('click', function retryC() {
                v.muted = true; v.play().catch(function () {});
                document.removeEventListener('click', retryC);
            }, { once: true });
        });
    }
}

// ══════════════════════════════════════════════
// GALERIA FOTOS — Seção "Conheça o Prédio" (só fotos)
// ══════════════════════════════════════════════
var IMG_STYLE = 'width:100%;aspect-ratio:16/9;object-fit:cover;display:block;';

function carregarGaleriaPredia() {
    var main = document.getElementById('gallery-main');
    if (!main) return;

    fetch('galeria_home.json?nc=' + Date.now())
        .then(function (r) { return r.json(); })
        .then(function (d) {
            var fotos = (d && d.fotos && d.fotos.length)
                ? d.fotos
                : ['fotos_predio/foto_predio_1.jpg','fotos_predio/foto_predio_2.jpg','fotos_predio/foto_predio_3.jpg'];
            renderGaleria(fotos);
        })
        .catch(function () {
            renderGaleria(['fotos_predio/foto_predio_1.jpg','fotos_predio/foto_predio_2.jpg','fotos_predio/foto_predio_3.jpg']);
        });
}

function renderGaleria(fotos) {
    var main   = document.getElementById('gallery-main');
    var thumbs = document.getElementById('gallery-thumbnails');
    if (!main) return;

    // Foto principal
    main.innerHTML = '';
    if (fotos.length) {
        var img = document.createElement('img');
        img.src = fotos[0];
        img.alt = 'Foto do prédio';
        img.style.cssText = IMG_STYLE;
        img.onerror = function () { this.src = 'fotos_predio/foto_predio_1.jpg'; };
        main.appendChild(img);
    }

    // Miniaturas
    if (!thumbs) return;
    thumbs.innerHTML = '';
    fotos.forEach(function (src, i) {
        var img = document.createElement('img');
        img.src = src;
        img.alt = 'Foto ' + (i + 1);
        img.style.cssText = 'cursor:pointer;';
        if (i === 0) { img.classList.add('active'); img.style.borderColor = 'rgb(30,136,229)'; img.style.opacity = '1'; }
        img.onerror = function () { this.style.display = 'none'; };
        img.addEventListener('click', function () {
            thumbs.querySelectorAll('img').forEach(function (t) {
                t.classList.remove('active');
                t.style.borderColor = 'transparent';
                t.style.opacity = '0.7';
            });
            img.classList.add('active');
            img.style.borderColor = 'rgb(30,136,229)';
            img.style.opacity = '1';
            main.innerHTML = '';
            var ni = document.createElement('img');
            ni.src = src; ni.alt = 'Foto'; ni.style.cssText = IMG_STYLE;
            main.appendChild(ni);
        });
        thumbs.appendChild(img);
    });
}

// ══════════════════════════════════════════════
// PONTOS ESTRATÉGICOS — slideshow como clientes
// ══════════════════════════════════════════════
var _pontoTimers = [];
function carregarPontos() {
    var grid = document.getElementById('pontos-grid');
    if (!grid) return;

    fetch('pontos_estrategicos.json?nc=' + Date.now())
        .then(function (r) { return r.json(); })
        .then(function (d) {
            var pts = d.pontos || [];
            if (!pts.length) { grid.innerHTML = ''; return; }
            _pontoTimers.forEach(clearInterval); _pontoTimers = [];
            grid.innerHTML = pts.map(function (p) {
                // Suporta campo antigo "imagem" e novo "fotos"
                var fotos = p.fotos && p.fotos.length ? p.fotos
                    : (p.imagem ? [p.imagem] : []);
                var hasImg = fotos.length > 0;
                var idAttr = 'ponto-stage-' + p.id;
                var slides = fotos.map(function (f, i) {
                    return '<img class="ponto-slide'+(i===0?' ponto-slide-ativo':'')+'" src="'+esc(f)+'" alt="'+esc(p.nome)+'">';
                }).join('');
                return '<div class="ponto-card">'
                    + '<div class="ponto-slide-stage" id="'+idAttr+'">'
                    + (hasImg ? slides : '')
                    + '</div>'
                    + '<div class="ponto-overlay"></div>'
                    + '<div class="ponto-nome">'+esc(p.nome)+'</div>'
                    + '</div>';
            }).join('');

            // Iniciar slideshow em cada ponto
            pts.forEach(function (p) {
                var fotos = p.fotos && p.fotos.length ? p.fotos : (p.imagem ? [p.imagem] : []);
                if (fotos.length <= 1) return;
                var stage = document.getElementById('ponto-stage-' + p.id);
                if (!stage) return;
                var idx = 0;
                var t = setInterval(function () {
                    var slides = stage.querySelectorAll('.ponto-slide');
                    if (!slides.length) return;
                    slides[idx].classList.remove('ponto-slide-ativo');
                    idx = (idx + 1) % slides.length;
                    slides[idx].classList.add('ponto-slide-ativo');
                }, 3000);
                _pontoTimers.push(t);
            });
        })
        .catch(function () {
            var fb = ['Ao lado do Atacadão Dia a Dia','Próximo à Câmara Municipal','Entrada do Novo Gama','Próximo ao Vapt Vupt'];
            if (document.getElementById('pontos-grid'))
                document.getElementById('pontos-grid').innerHTML = fb.map(function (n) {
                    return '<div class="ponto-card"><div class="ponto-slide-stage"></div><div class="ponto-overlay"></div><div class="ponto-nome">'+esc(n)+'</div></div>';
                }).join('');
        });
}

// ══════════════════════════════════════════════
// CLIENTES — slides automáticos de fotos
// ══════════════════════════════════════════════
function carregarClientes() {
    var grid = document.getElementById('clientes-grid');
    if (!grid) return;

    fetch('clientes.json?nc=' + Date.now())
        .then(function (r) { return r.json(); })
        .then(function (d) {
            var list = (d.clientes || []).filter(function (c) { return c.ativo !== false; });
            if (!list.length) { grid.innerHTML = ''; return; }

            grid.innerHTML = list.map(function (c) {
                var fotos = c.fotos || [];
                var imgs  = fotos.map(function (f, i) {
                    return '<img class="' + (i === 0 ? 'cli-ativo' : '') + '" src="' + f + '" alt="' + esc(c.nome) + '" loading="lazy">';
                }).join('');
                return '<div class="cli-card">'
                    + '<div class="cli-stage">' + (imgs || '<div style="height:100%;display:flex;align-items:center;justify-content:center;font-size:50px;opacity:.25">📷</div>') + '</div>'
                    + '<div class="cli-nome-bar">' + esc(c.nome) + '</div>'
                    + '</div>';
            }).join('');

            // Auto-slide
            grid.querySelectorAll('.cli-stage').forEach(function (stage) {
                var imgs = stage.querySelectorAll('img');
                if (imgs.length <= 1) return;
                var idx = 0;
                setInterval(function () {
                    imgs[idx].classList.remove('cli-ativo');
                    idx = (idx + 1) % imgs.length;
                    imgs[idx].classList.add('cli-ativo');
                }, 2600 + Math.random() * 600);
            });
        })
        .catch(function () { grid.innerHTML = ''; });
}

// ══════════════════════════════════════════════
// SMOOTH SCROLL
// ══════════════════════════════════════════════
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function (a) {
        if (a.closest('#nav-menu')) return; // links do menu tratados em initMenuMobile
        a.addEventListener('click', function (e) {
            var h = this.getAttribute('href');
            if (!h || h === '#') return;
            var t = document.querySelector(h);
            if (t) { e.preventDefault(); t.scrollIntoView({ behavior: 'smooth' }); }
        });
    });
}

// ══════════════════════════════════════════════
// MAPAS — abre app no celular, navegador no desktop
// ══════════════════════════════════════════════
function abrirMapa(tipo) {
    var ua = navigator.userAgent || '';
    var isIOS     = /iPad|iPhone|iPod/.test(ua);
    var isAndroid = /Android/i.test(ua);
    var lat = '-16.051749';
    var lng = '-48.030162';
    var q   = encodeURIComponent('Centro Comercial Logos, Novo Gama, GO');

    if (!isIOS && !isAndroid) {
        // Desktop: abre no navegador em nova aba
        var web = {
            google: 'https://maps.google.com/?q=Centro+Comercial+Logos+Novo+Gama+GO',
            waze:   'https://www.waze.com/en/live-map/directions/br/go/colegio-logos?place=ChIJF6DO0hGBWZMRo1wHMFodeN8',
            apple:  'https://maps.apple.com/?address=Av.%20Perimetral%2C%20Novo%20Gama%2C%20GO'
        };
        if (web[tipo]) window.open(web[tipo], '_blank');
        return;
    }

    // Mobile: tenta abrir no app nativo
    if (tipo === 'google') {
        if (isIOS) {
            window.location.href = 'comgooglemaps://?q=' + q + '&center=' + lat + ',' + lng;
            setTimeout(function () {
                window.location.href = 'https://maps.google.com/?q=Centro+Comercial+Logos+Novo+Gama+GO';
            }, 1500);
        } else {
            // Android — intent abre Google Maps ou Maps padrão
            window.location.href = 'geo:' + lat + ',' + lng + '?q=' + q;
        }
    } else if (tipo === 'waze') {
        window.location.href = 'waze://?ll=' + lat + ',' + lng + '&navigate=yes';
        setTimeout(function () {
            window.location.href = 'https://waze.com/ul?ll=' + lat + ',' + lng + '&navigate=yes';
        }, 1500);
    } else if (tipo === 'apple') {
        if (isIOS) {
            window.location.href = 'maps://?q=' + q + '&ll=' + lat + ',' + lng;
        } else {
            // Android não tem Apple Maps — usa Google Maps
            window.location.href = 'geo:' + lat + ',' + lng + '?q=' + q;
        }
    }
}

// ── helper ──
function esc(s) {
    return String(s || '').replace(/[&<>"']/g, function (c) {
        return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
    });
}
