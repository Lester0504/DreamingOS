// SPDX-License-Identifier: GPL-2.0-or-later
/* XLSX is an interchange container, not an executable spreadsheet. Read only
 * the channel sheet and shared strings, with explicit row/expanded byte limits.
 * The Chinese headings are a data contract; implementation is native C. */
#define _GNU_SOURCE
#include "iptv.h"
#include <archive.h>
#include <archive_entry.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define XLSX_MAX (1024*1024)
#define XML_MAX (8*1024*1024)
struct column { const char *title,*key; int type; };
static const struct column columns[]={
 {"频道名称","name",0},{"频道号","number",1},{"分类","category_name",0},
 {"排序","position",1},{"启用","enabled",2},{"外部直连","mode",3},
 {"输入地址","source_url",0},{"图标地址","logo_url",0},{"EPG频道ID","epg_id",0},
 {"切片容器","hls_container",0},{"EPG源ID","epg_source_id",0},{"来源接口ID","input_id",0},{"时移分钟","timeshift_minutes",1},{"节目号","program_id",1},{"RTSP传输","rtsp_transport",0},{"HTTP User-Agent","user_agent",0},{"视频编码","video_encoder",0},{"音频编码","audio_encoder",0},{"视频码率Kbps","video_bitrate_kbps",1},{"音频码率Kbps","audio_bitrate_kbps",1},{NULL,NULL,0}
};
static int field(const char *s){for(int i=0;columns[i].title;i++)if(!strcmp(columns[i].title,s))return i;return -1;}
static xmlNodePtr child(xmlNodePtr n,const char *name)
{for(n=n?n->children:NULL;n;n=n->next)if(n->type==XML_ELEMENT_NODE&&!xmlStrcmp(n->name,BAD_CAST name))return n;return NULL;}
static xmlDocPtr document(const char *s)
{if(!s||strstr(s,"<!DOCTYPE")||strstr(s,"<!ENTITY"))return NULL;return xmlReadMemory(s,(int)strlen(s),"workbook.xml",NULL,XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);}
static void error_row(struct json_object *row,const char *code,const char *name)
{json_object_object_add(row,"parse_error",json_object_new_string(code));json_object_object_add(row,"unsupported_column",json_object_new_string(name));}
static int is_false(const char *s){return !*s||!strcmp(s,"0")||!strcmp(s,"否")||!strcasecmp(s,"false");}
static int is_true(const char *s){return !strcmp(s,"1")||!strcmp(s,"是")||!strcasecmp(s,"true");}
struct json_object *iptv_workbook_read(const char *base64,struct iptv_error *e)
{
 size_t n=strlen(base64);if(!n||n%4||n>4*((XLSX_MAX+2)/3))return iptv_fail(e,413,"workbook_size_invalid","base64");
 for(size_t i=0;i<n;i++)if(!isalnum((unsigned char)base64[i])&&base64[i]!='+'&&base64[i]!='/'&&!(base64[i]=='='&&i>=n-2))return iptv_fail(e,400,"invalid_base64","base64");
 unsigned char *zip=malloc(n);if(!zip)return iptv_fail(e,503,"out_of_memory","");
 int length=EVP_DecodeBlock(zip,(const unsigned char*)base64,(int)n);if(length<0){free(zip);return iptv_fail(e,400,"invalid_base64","");}
 if(base64[n-1]=='=')length--;if(base64[n-2]=='=')length--;
 struct archive *a=archive_read_new();archive_read_support_format_zip(a);struct json_object *parts=json_object_new_object(),*rows=NULL,*strings=json_object_new_array();
 struct archive_entry *entry=NULL;size_t total=0;int count=0,status;
 if(archive_read_open_memory(a,zip,(size_t)length)!=ARCHIVE_OK)goto invalid;
 while((status=archive_read_next_header(a,&entry))==ARCHIVE_OK){
  const char *name=archive_entry_pathname(entry);la_int64_t size=archive_entry_size(entry);
  if(++count>128||size<0||size>XML_MAX||total+(size_t)size>16*1024*1024)goto invalid;
  total+=(size_t)size;
  if(!name||archive_entry_filetype(entry)!=AE_IFREG||strncmp(name,"xl/",3)){archive_read_data_skip(a);continue;}
  char *data=malloc((size_t)size+1);if(!data)goto invalid;
  size_t got=0;while(got<(size_t)size){la_ssize_t v=archive_read_data(a,data+got,(size_t)size-got);if(v<=0)break;got+=(size_t)v;}
  if(got!=(size_t)size||memchr(data,0,got)){free(data);goto invalid;}data[got]=0;
  json_object_object_add(parts,name,json_object_new_string(data));free(data);
 }
 if(status!=ARCHIVE_EOF)goto invalid;
 xmlDocPtr workbook=document(iptv_string(parts,"xl/workbook.xml")),rels=document(iptv_string(parts,"xl/_rels/workbook.xml.rels"));
 char relation[128]="",sheet_path[256]="";
 xmlNodePtr sheets=workbook?child(xmlDocGetRootElement(workbook),"sheets"):NULL;
 for(xmlNodePtr s=sheets?sheets->children:NULL;s;s=s->next){if(s->type!=XML_ELEMENT_NODE)continue;xmlChar *name=xmlGetProp(s,BAD_CAST "name");
  if(name&&!xmlStrcmp(name,BAD_CAST "频道")){xmlChar *id=xmlGetNsProp(s,BAD_CAST "id",BAD_CAST "http://schemas.openxmlformats.org/officeDocument/2006/relationships");if(id){snprintf(relation,sizeof(relation),"%s",id);xmlFree(id);}}xmlFree(name);}
 xmlNodePtr rr=rels?xmlDocGetRootElement(rels):NULL;
 for(xmlNodePtr s=rr?rr->children:NULL;s;s=s->next){if(s->type!=XML_ELEMENT_NODE)continue;xmlChar *id=xmlGetProp(s,BAD_CAST "Id"),*target=xmlGetProp(s,BAD_CAST "Target"),*mode=xmlGetProp(s,BAD_CAST "TargetMode");
  if(id&&target&&!strcmp((char*)id,relation)&&!mode&&!strstr((char*)target,".."))snprintf(sheet_path,sizeof(sheet_path),target[0]=='/'?"%s":"xl/%s",target[0]=='/'?(char*)target+1:(char*)target);
  xmlFree(id);xmlFree(target);xmlFree(mode);}
 if(workbook)xmlFreeDoc(workbook);if(rels)xmlFreeDoc(rels);
 xmlDocPtr shared=document(iptv_string(parts,"xl/sharedStrings.xml"));
 if(shared){xmlNodePtr root=xmlDocGetRootElement(shared);for(xmlNodePtr s=root?root->children:NULL;s;s=s->next){if(s->type==XML_ELEMENT_NODE&&!xmlStrcmp(s->name,BAD_CAST "si")){xmlChar *v=xmlNodeGetContent(s);json_object_array_add(strings,json_object_new_string(v?(char*)v:""));xmlFree(v);}}xmlFreeDoc(shared);}
 xmlDocPtr sheet=document(iptv_string(parts,sheet_path));if(!sheet)goto invalid;
 xmlNodePtr sheetdata=child(xmlDocGetRootElement(sheet),"sheetData");char headings[64][128]={{0}};int first=1,rownum=0;
 rows=json_object_new_array();
 for(xmlNodePtr row=sheetdata?sheetdata->children:NULL;row;row=row->next){
  if(row->type!=XML_ELEMENT_NODE||xmlStrcmp(row->name,BAD_CAST "row"))continue;
  if(++rownum>1001){xmlFreeDoc(sheet);goto invalid;}
  struct json_object *item=json_object_new_object();int any=0,previous_col=0;
  json_object_object_add(item,"line",json_object_new_int(rownum));
  for(xmlNodePtr cell=row->children;cell;cell=cell->next){
   if(cell->type!=XML_ELEMENT_NODE||xmlStrcmp(cell->name,BAD_CAST "c"))continue;
   xmlChar *ref=xmlGetProp(cell,BAD_CAST "r"),*type=xmlGetProp(cell,BAD_CAST "t");int col=0;
   for(const xmlChar *p=ref;p&&*p>='A'&&*p<='Z';p++)col=col*26+*p-'A'+1;
   if(!ref)col=previous_col+1;previous_col=col;
   xmlNodePtr value=child(cell,type&&!xmlStrcmp(type,BAD_CAST "inlineStr")?"is":"v");xmlChar *text=value?xmlNodeGetContent(value):NULL;const char *v=text?(char*)text:"";
   if(type&&!xmlStrcmp(type,BAD_CAST "s")){char *end=NULL;long index=strtol(v,&end,10);v=*v&&end&&!*end&&index>=0&&(size_t)index<json_object_array_length(strings)?json_object_get_string(json_object_array_get_idx(strings,(size_t)index)):"";}
   if(col<1||col>64||strlen(v)>2048){error_row(item,"workbook_cell_invalid","cell");}
   else if(child(cell,"f")){any=1;error_row(item,"workbook_formula_not_supported",first?"header":headings[col-1]);}
   else if(first){if(strlen(v)>=sizeof(headings[0]))error_row(item,"workbook_header_invalid","header");else snprintf(headings[col-1],sizeof(headings[0]),"%s",v);}
   else if(*v){
    any=1;const char *heading=headings[col-1];int f=field(heading);
    if(child(cell,"f"))error_row(item,"workbook_formula_not_supported",heading);
    else if(f<0){
     /* Unsupported configured behaviours must never disappear in migration. */
     if(!strcmp(heading,"输入协议")){if(strcmp(v,"http")&&strcmp(v,"https")&&strcmp(v,"udp")&&strcmp(v,"rtp")&&strcmp(v,"rtsp")&&strcmp(v,"rtmp"))error_row(item,"input_protocol_unsupported",heading);}
     else if((!strcmp(heading,"视频编码")||!strcmp(heading,"音频编码"))&&!strcmp(v,"copy")){}
     else if(!is_false(v))error_row(item,"workbook_column_not_supported",heading);
    }else if(columns[f].type==1){char *end=NULL;long num=strtol(v,&end,10);if(!end||*end||num<0||num>100000)error_row(item,"workbook_number_invalid",heading);else json_object_object_add(item,columns[f].key,json_object_new_int((int)num));}
    else if(columns[f].type==2||columns[f].type==3){if(!is_true(v)&&!is_false(v))error_row(item,"workbook_boolean_invalid",heading);else json_object_object_add(item,columns[f].key,columns[f].type==3?json_object_new_string(is_true(v)?"external":"managed"):json_object_new_boolean(is_true(v)));}
    else json_object_object_add(item,columns[f].key,json_object_new_string(v));
   }
   xmlFree(ref);xmlFree(type);xmlFree(text);
  }
  if(first){int name=0,url=0;for(int i=0;i<64;i++){name|=!strcmp(headings[i],"频道名称");url|=!strcmp(headings[i],"输入地址");}first=0;if(!name||!url||*iptv_string(item,"parse_error")){json_object_put(item);xmlFreeDoc(sheet);goto invalid;}}
  if(any)json_object_array_add(rows,item);else json_object_put(item);
 }
 xmlFreeDoc(sheet);
 if(first)goto invalid;
 goto done;
invalid:if(rows)json_object_put(rows);rows=iptv_fail(e,422,"workbook_invalid_or_limit_exceeded","base64");
done:archive_read_free(a);free(zip);json_object_put(parts);json_object_put(strings);return rows;
}
static int add_file(struct archive *a,const char *name,const char *text)
{
 struct archive_entry *e=archive_entry_new();archive_entry_set_pathname(e,name);archive_entry_set_size(e,strlen(text));archive_entry_set_filetype(e,AE_IFREG);archive_entry_set_perm(e,0600);
 int rc=archive_write_header(a,e);if(rc==ARCHIVE_OK&&archive_write_data(a,text,strlen(text))!=(la_ssize_t)strlen(text))rc=ARCHIVE_FATAL;archive_entry_free(e);return rc;
}
static void cell(FILE *f,const char *s)
{xmlChar *escaped=xmlEncodeSpecialChars(NULL,BAD_CAST(s?s:""));fprintf(f,"<c t=\"inlineStr\"><is><t xml:space=\"preserve\">%s</t></is></c>",escaped?(char*)escaped:"");xmlFree(escaped);}
struct json_object *iptv_workbook_write(sqlite3 *db,int template,struct iptv_error *e)
{
 struct json_object *list=iptv_list(db,"channels",e),*cats=iptv_list(db,"categories",e),*items=NULL,*groups=NULL,*result=NULL;
 if(!list||!cats)goto done;json_object_object_get_ex(list,"items",&items);json_object_object_get_ex(cats,"items",&groups);
 if(!template)for(size_t i=0;i<json_object_array_length(items);i++){
  if(iptv_integer(json_object_array_get_idx(items,i),"has_access_url",0)){
   iptv_fail(e,409,"source_access_export_unsupported","channels");goto done;
  }
 }
 char *sheet=NULL;size_t len=0;FILE *f=open_memstream(&sheet,&len);if(!f)goto bad;
 fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row>",f);
 for(int i=0;columns[i].title;i++)cell(f,columns[i].title);fputs("</row>",f);
 for(size_t i=0;!template&&i<json_object_array_length(items);i++){
  struct json_object *c=json_object_array_get_idx(items,i);fputs("<row>",f);
  for(int n=0;columns[n].title;n++){char num[40];const char *value=iptv_string(c,columns[n].key);
   if(columns[n].type==1){int fallback=!strcmp(columns[n].key,"video_bitrate_kbps")?2000:!strcmp(columns[n].key,"audio_bitrate_kbps")?192:0;snprintf(num,sizeof(num),"%d",iptv_integer(c,columns[n].key,fallback));value=num;}
   if(columns[n].type==2)value=iptv_integer(c,columns[n].key,0)?"是":"否";
   if(columns[n].type==3)value=!strcmp(iptv_string(c,"mode"),"external")?"是":"否";
   if(!strcmp(columns[n].key,"category_name"))for(size_t j=0;j<json_object_array_length(groups);j++){struct json_object *g=json_object_array_get_idx(groups,j);if(!strcmp(iptv_string(g,"id"),iptv_string(c,"category_id")))value=iptv_string(g,"name");}
   cell(f,value);
  }fputs("</row>",f);
 }
 fputs("</sheetData></worksheet>",f);fclose(f);
 struct archive *a=archive_write_new();unsigned char *zip=malloc(XLSX_MAX);size_t used=0;int rc=ARCHIVE_OK;
 if(!zip){archive_write_free(a);free(sheet);goto bad;}
 archive_write_set_format_zip(a);archive_write_set_options(a,"zip:compression=deflate");
 if(archive_write_open_memory(a,zip,XLSX_MAX,&used)!=ARCHIVE_OK)rc=ARCHIVE_FATAL;
 const char *paths[]={"[Content_Types].xml","_rels/.rels","xl/workbook.xml","xl/_rels/workbook.xml.rels","xl/worksheets/sheet1.xml"};
 const char *texts[]={"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>",
 "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>",
 "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"频道\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>",
 "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/></Relationships>",sheet};
 for(int i=0;rc==ARCHIVE_OK&&i<5;i++)rc=add_file(a,paths[i],texts[i]);
 if(archive_write_close(a)!=ARCHIVE_OK)rc=ARCHIVE_FATAL;archive_write_free(a);free(sheet);
 if(rc!=ARCHIVE_OK){free(zip);goto bad;}
 char *b64=malloc(4*((used+2)/3)+1);if(!b64){free(zip);goto bad;}EVP_EncodeBlock((unsigned char*)b64,zip,(int)used);free(zip);
 result=json_object_new_object();json_object_object_add(result,"base64",json_object_new_string(b64));free(b64);json_object_object_add(result,"filename",json_object_new_string(template?"iptv-template.xlsx":"iptv-channels.xlsx"));json_object_object_add(result,"format",json_object_new_string("xlsx"));goto done;
bad:iptv_fail(e,503,"workbook_export_failed","");
done:if(list)json_object_put(list);if(cats)json_object_put(cats);return result;
}
