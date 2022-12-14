function emojiButtonList_Initialize(t,l){return new emojiButtonList(t,l)}
function emojiButtonList(t,l){function A(a){a="&#"+a+";";var e=w("div");e.innerHTML=a;var d=w("div");d.className="emoji";d.innerHTML=a;f.appendChild(d);d.onclick=function(){if(null===c||x("onEmojiClick")){var g=e.innerHTML;if(x("onEmojiClick"))b.onEmojiClick(g)}else if(g=e.innerHTML,k.selection)c.focus(),k.selection.createRange().text=g,c.focus();else if(c.selectionStart||0===c.selectionStart){var m=c.selectionStart,p=c.selectionEnd,B=c.scrollTop;c.value=c.value.substring(0,m)+g+c.value.substring(p,
    c.value.length);c.focus();c.selectionStart=m+g.length;c.selectionEnd=m+g.length;c.scrollTop=B}else c.value+=g,c.focus()}}function C(a){var e;a.preventDefault();a.cancelBubble=!0;if("block"!==f.style.display){u("block");a=n;var d=0;for(e=0;a&&!isNaN(a.offsetLeft)&&!isNaN(a.offsetTop);)d+=a.offsetLeft-a.scrollLeft,e+=a.offsetTop-a.scrollTop,a=a.offsetParent;a=d;d=a+b.xAlignMargin;"center"===b.dropDownXAlign&&(d=a-(f.offsetWidth/2-n.offsetWidth/2));if(d+f.offsetWidth>q.innerWidth||"right"===b.dropDownXAlign)d=
    a-(f.offsetWidth-n.offsetWidth)-b.xAlignMargin;d<b.xAlignMargin&&(d=b.xAlignMargin);a=e+n.offsetHeight+b.yAlignMargin;if(a+f.offsetHeight>q.innerHeight||"top"===b.dropDownYAlign)a=e-(f.offsetHeight+b.yAlignMargin);a<b.yAlignMargin&&(a=b.yAlignMargin);f.style.top=a+"px";f.style.left=d+"px"}else u("none")}function y(){u("none")}function u(a){f.style.display!==a&&(f.style.display=a)}function w(a){a=null==a?"div":a.toLowerCase();var e="text"===a;v.hasOwnProperty(a)||(v[a]=e?k.createTextNode(""):k.createElement(a));
    return v[a].cloneNode(!1)}function z(a){var e=null;h(a)&&(r.hasOwnProperty(a)&&null!==r[a]||(r[a]=k.getElementById(a)),e=r[a]);return e}function x(a){return null!==b&&h(b[a])&&"function"===typeof b[a]}function h(a){return void 0!==a&&null!==a&&""!==a}var b={},r={},v={},k=null,q=null,D=this,n=null,c=null,f=null;this.setOptions=function(a){b=null!==a&&"object"===typeof a?a:{};h(b.emojiRangesToShow)||(b.emojiRangesToShow=[[128513,128591],[9986,10160],[128640,128704]]);h(b.dropDownXAlign)||(b.dropDownXAlign=
    "left");h(b.dropDownYAlign)||(b.dropDownYAlign="bottom");h(b.textBoxID)||(b.textBoxID=null);h(b.xAlignMargin)||(b.xAlignMargin=0);h(b.yAlignMargin)||(b.yAlignMargin=0)};(function(a,e){l=h(l)?l:{};k=a;q=e;D.setOptions(l);n=z(t);c=z(b.textBoxID);f=document.createElement("div");f.className="emoji-drop-down custom-scroll-bars";f.style.display="none";k.body.appendChild(f);for(var d=b.emojiRangesToShow.length,g=0;g<d;g++)for(var m=b.emojiRangesToShow[g],p=m[0];p<m[1];p++)A(p);k.body.addEventListener("click",
    y);q.addEventListener("resize",y);n.addEventListener("click",C)})(document,window)};
var margin = 10,
    instance1 = new emojiButtonList( "emoji", {
        dropDownXAlign: "left",
        textBoxID: "inputext",
        yAlignMargin: margin,
        xAlignMargin: margin
    } );
function emojiClickEvent( emojiText ) {
    document.title += " " + emojiText;
}