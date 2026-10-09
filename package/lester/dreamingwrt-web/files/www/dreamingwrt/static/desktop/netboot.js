import {mount} from '/plugins/native/netboot.js?v=20261002-netboot-04';
const root=document.documentElement,media=matchMedia('(prefers-color-scheme: dark)');
function theme() {
  let family=localStorage.getItem('dreamingwrt.web.themeFamily')||'traditional';
  const preference=localStorage.getItem('dreamingwrt.web.themePref')||'system';
  root.dataset.themeResolved=preference==='dark'||preference==='system'&&media.matches?'dark':'light';
  try{if(parent!==window&&parent.location.origin===location.origin&&parent.DWRT_DESKTOP_HOST){root.dataset.desktopApp='true';family=parent.document.documentElement.dataset.themeFamily||family;root.dataset.themeResolved=parent.document.documentElement.dataset.themeResolved||root.dataset.themeResolved;}}catch(_){/* Standalone host uses its own theme. */}
  root.dataset.themeFamily=['traditional','frosted-glass','liquid-glass'].includes(family)?family:'traditional';
}
theme();let observer,chromeObserver,chromeResize,chromeFrame=0;
function reserveChrome() {
  chromeFrame=0;let inset=0;
  try {
    const frame=window.frameElement,dock=parent.document.getElementById('desktopDock');
    if(frame&&dock&&parent.DWRT_DESKTOP_HOST) {
      const f=frame.getBoundingClientRect(),d=dock.getBoundingClientRect();
      if(d.width&&d.height&&d.left<f.right&&d.right>f.left&&d.top<f.bottom&&d.bottom>f.top)inset=Math.max(0,f.bottom-d.top);
    }
  } catch(_){}
  root.style.setProperty('--nb-host-bottom-inset',`${Math.ceil(inset)}px`);
}
function scheduleChrome(){if(!chromeFrame)chromeFrame=requestAnimationFrame(reserveChrome);}
try{if(parent!==window&&parent.location.origin===location.origin){observer=new MutationObserver(theme);observer.observe(parent.document.documentElement,{attributes:true,attributeFilter:['data-theme-family','data-theme-resolved']});}}catch(_){}
try {
  if(window.frameElement&&parent.DWRT_DESKTOP_HOST) {
    chromeObserver=new MutationObserver(scheduleChrome);
    chromeObserver.observe(window.frameElement.closest('article'),{attributes:true,attributeFilter:['style','class','hidden']});
    chromeResize=new ResizeObserver(scheduleChrome);
    chromeResize.observe(parent.document.getElementById('desktopDock'));chromeResize.observe(window.frameElement);
  }
}catch(_){}
addEventListener('resize',scheduleChrome);scheduleChrome();
addEventListener('storage',theme);media.addEventListener('change',theme);
const instance=mount({root:document.getElementById('netbootRoot'),ui:window.DWRT_UI_KIT||{}});
addEventListener('pagehide',()=>{instance.unmount();observer?.disconnect();chromeObserver?.disconnect();chromeResize?.disconnect();cancelAnimationFrame(chromeFrame);removeEventListener('resize',scheduleChrome);removeEventListener('storage',theme);media.removeEventListener('change',theme);},{once:true});
