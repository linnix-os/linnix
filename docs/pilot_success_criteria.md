## Pilot Success Criteria

To validate that Linnix is delivering value, we'll measure success by:

1. **Continuous Operation**  
   Linnix runs on at least one production node for 30+ consecutive days without manual intervention.

2. **Useful Incident Detection**  
   At least one "node slow" incident where Linnix:
   - Correctly identifies the top offending pod(s) in `top_pods` table
   - Provides a `suggested_next_step` judged "useful" by the on-call SRE
   - Receives "useful" feedback via Slack or CLI

3. **Low Noise Threshold**  
   Average of ≤10 alerts per day per node at default configuration.

4. **Feedback Loop Health**  
   At least 5 feedback entries collected (useful/noise/wrong) across all alerts.

### How to Provide Feedback

**Via Slack**: Click "👍 Useful" or "👎 Noise" buttons on alert messages.

**Via CLI**:
```bash
linnix feedback <insight-id> --label useful|noise|wrong
```

Your feedback helps tune Linnix for your environment and will inform future AI improvements.
