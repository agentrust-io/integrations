"""Validate TRACE pointer shape for immutable source artifacts without attesting them."""
import argparse
import json
from pathlib import Path
from trace_references import behavior_reference
from runner import relative_file

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--lock',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();lock=json.loads(a.lock.read_text());items=[]
    for item in lock['files']:
        path=relative_file(a.lock.parent,item['path'])
        ref=behavior_reference(path,item['url'])
        items.append({'file':item['path'],'reference':ref.model_dump(exclude_none=True),'reference_shape_validated':True,
                      'signature_verification':'not_measured','assurance':'public_vendor_log','trace_record_emitted':False})
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(items,indent=2)+'\n')
    print(len(items),'reference shapes validated; no signatures or effects attested')
