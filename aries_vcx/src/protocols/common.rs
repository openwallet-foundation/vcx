use messages2::{
    decorators::thread::Thread,
    msg_fields::protocols::report_problem::{ProblemReport, ProblemReportContent, ProblemReportDecorators},
};
use uuid::Uuid;

pub fn build_problem_report_msg(comment: Option<String>, thread_id: &str) -> ProblemReport {
    let id = Uuid::new_v4().to_string();
    let mut content = ProblemReportContent::new(comment.unwrap_or_default());

    let mut decorators = ProblemReportDecorators::default();
    decorators.thread = Some(Thread::new(thread_id.to_owned()));

    ProblemReport::with_decorators(id, content, decorators)
}

#[cfg(test)]
#[cfg(feature = "general_test")]
mod test {
    use crate::protocols::common::build_problem_report_msg;
    use crate::utils::devsetup::{was_in_past, SetupMocks};
    use messages::a2a::MessageId;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_holder_build_problem_report_msg() {
        let _setup = SetupMocks::init();
        let msg = build_problem_report_msg(Some("foo".into()), "12345");

        assert_eq!(msg.id, MessageId::default());
        assert_eq!(msg.thread.unwrap().thid.unwrap(), "12345");
        assert!(was_in_past(
            &msg.timing.unwrap().out_time.unwrap(),
            chrono::Duration::milliseconds(100),
        )
        .unwrap());
    }
}
