function openChat(){
alert('Open chatbot (wireframe)')
}


// Theme toggle
const btn = document.getElementById('theme-toggle')
if(btn){btn.addEventListener('click', ()=>{document.body.classList.toggle('dark')})}