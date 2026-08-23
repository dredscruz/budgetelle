// Minimal XLSX writer (SpreadsheetML 2003 XML — opens natively in Excel, Google Sheets, Numbers)
function xlsxSheets(sheets){
  // sheets: [{name, rows:[[cell,...],...]}] cell: string|number|{v,f} (f=formula)
  const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const xml=sheets.map(sh=>{
    const rows=sh.rows.map(r=>`<Row>${r.map(c=>{
      if(c===null||c===undefined||c==='')return '<Cell/>';
      if(typeof c==='object'&&c.f)return `<Cell><F>${esc(c.f)}</F></Cell>`;
      if(typeof c==='number'&&!isNaN(c))return `<Cell><Data ss:Type="Number">${c}</Data></Cell>`;
      return `<Cell><Data ss:Type="String">${esc(c)}</Data></Cell>`;
    }).join('')}</Row>`).join('');
    return `<Worksheet ss:Name="${esc(sh.name).slice(0,31)}"><Table>${rows}</Table>
    <WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel"><FreezePanes/><SplitHorizontal>1</SplitHorizontal><TopRowBottomPane>1</TopRowBottomPane><ActivePane>2</ActivePane></WorksheetOptions></Worksheet>`;
  }).join('');
  return `<?xml version="1.0"?><?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">${xml}</Workbook>`;
}
function downloadWorkbook(blob,name){
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),4000);
}
