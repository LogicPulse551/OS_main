import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from kconc import actor_run


class ActorBatchTests(unittest.TestCase):
    def test_pages_cover_the_same_search_without_repeating(self):
        plan = actor_run.make_plan(3,5,90)
        pages = [actor_run.make_plan(3,5,32,start) for start in (0,32,64)]
        self.assertEqual([x for page in pages for x in page['orders']],plan['orders'])
        self.assertEqual([p['selected'] for p in pages],[32,32,26])
        self.assertEqual(pages[-1]['unexplored'],64)
        with self.assertRaises(ValueError):
            actor_run.make_plan(3,5,32,90)

    def test_interrupted_batch_keeps_each_planned_slot(self):
        plan = actor_run.make_plan(3,5,4)
        ledger = actor_run.unverified_cases(plan,'CASE 0 012012\nEND 0 load=0 unload=0 clean=1\nCASE 1 001122\n')
        self.assertEqual([r['status'] for r in ledger],['unverified','unverified','not_observed','not_observed'])
        self.assertEqual(actor_run.capacity(ledger,2)['unevaluated'],4)

    def test_unmatched_path_cannot_support_property(self):
        bad = {'status':'failed','index':0,'order':[0,1,2,0,1,2],
               'rows':[{'step':2,'role':2,'after':7}]}
        result = actor_run.capacity([bad],2)
        self.assertEqual((result['evaluated'],result['unevaluated'],result['witnesses']),(0,1,[]))
