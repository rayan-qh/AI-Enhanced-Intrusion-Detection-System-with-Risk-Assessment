const names = {BENIGN:'مرور طبيعي',PortScan:'مسح منافذ','Brute Force':'تخمين كلمات المرور',DoS:'حجب الخدمة','Web Attack':'هجوم ويب','Rare Attack':'هجمات نادرة'};
function text(id,value){document.getElementById(id).textContent=value;}
async function refresh(){
  try{
    const response=await fetch('/api/status');
    if(!response.ok) throw new Error('HTTP');
    const data=await response.json();
    text('state',data.message);
    const prediction=data.prediction;
    text('attack',prediction ? (names[prediction.attack_type] || prediction.attack_type) : 'غير متوفر');
    text('risk',prediction ? `درجة الخطورة ${prediction.risk_score ?? 'غير متوفر'} · ${prediction.risk_level}` : 'درجة الخطورة غير متوفرة');
    text('time',prediction ? `وقت الاستدلال ${new Date(prediction.timestamp*1000).toLocaleString('ar-SA')}` : '');
    const container=document.getElementById('probabilities');container.replaceChildren();
    for(const [name,value] of Object.entries(prediction?.class_probabilities || {})){
      const line=document.createElement('div');line.className='probability';
      const label=document.createElement('span');label.textContent=names[name] || name;
      const number=document.createElement('span');number.textContent=`${(value*100).toFixed(2)}%`;
      line.append(label,number);container.append(line);
    }
    text('snort',data.snort?.message || data.snort_error || 'لا يوجد تنبيه محفوظ');
    text('rule',data.snort ? `${data.snort.rule} · ${data.snort.fresh?'ملف محدث حديثًا':'سجل قديم'}` : '');
  }catch(error){text('state','تعذر الاتصال بالخادم؛ قد تكون القيم المعروضة قديمة');}
}
refresh();setInterval(refresh,5000);
